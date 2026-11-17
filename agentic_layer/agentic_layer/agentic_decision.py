# =============================================================================
# COUCHE AGENTIQUE — Decision Agent
# =============================================================================
# Ajoute deux capacités agentiques, SANS toucher au cœur décisionnel (qui reste
# en règles explicites auditables — c'est un choix assumé) :
#
#   1. AGIR (outils exécutables)
#      Le cœur PROPOSE des actions. La couche agentique les EXÉCUTE via des
#      outils réels (isoler une machine, bloquer une IP...), sous contrôle d'une
#      POLITIQUE (auto-exécution seulement si autorisée ; sinon, en attente de
#      validation humaine). Passage de "je recommande" à "j'agis".
#
#   2. RE-SOLLICITER avant d'escalader (perception active)
#      Pour un cas DOUTEUX, avant d'escalader au Niveau 2 (coûteux), l'agent
#      DÉCIDE de redemander d'abord aux détecteurs : "ré-analyse cette séquence"
#      (REANALYZE). Si le doute se lève localement, on évite l'escalade.
#
# Le cœur (corrélation, certitude, routage) n'est PAS modifié : la couche
# agit APRÈS la décision, en exécutant et en cherchant à lever le doute.
# =============================================================================

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Callable, Any

from .agent_bus import AgentBus, AgentRequest, AgentResponse, RequestType


class ActionPolicy(str, Enum):
    """Politique d'exécution des actions (contrôle humain vs autonomie)."""
    MANUAL = "manual"              # rien n'est exécuté : tout attend l'humain
    AUTO_IMMEDIATE_ONLY = "auto_immediate_only"  # exécute seulement les actions "immediate"
    AUTONOMOUS = "autonomous"      # exécute toutes les actions recommandées


@dataclass
class ActionExecution:
    """Trace de l'exécution d'une action (auditable)."""
    action_id: str
    name: str
    host: Optional[str]
    executed: bool
    result: str = ""
    reason: str = ""


@dataclass
class AgenticDecisionConfig:
    policy: ActionPolicy = ActionPolicy.AUTO_IMMEDIATE_ONLY
    # tenter de lever le doute avant d'escalader une investigation ?
    reassess_before_escalation: bool = True


class AgenticDecisionAgent:
    """
    Wrapper agentique autour du DecisionAgent.
    Donne : exécution outillée des actions + re-sollicitation avant escalade.
    """

    def __init__(self, decision_agent, bus: AgentBus,
                 tools: Optional[dict] = None,
                 config: Optional[AgenticDecisionConfig] = None,
                 name: str = "decision"):
        self.core = decision_agent        # cœur intact (règles auditables)
        self.bus = bus
        self.name = name
        self.config = config or AgenticDecisionConfig()
        # outils exécutables : action_id → fonction(host, payload) -> résultat
        # ex: {"D3-OTF": block_ip_fn, "isolate": isolate_host_fn}
        self.tools = tools or {}
        self.executions: list[ActionExecution] = []
        self.reassessments: list[dict] = []

    def decide(self, threat_verdicts=None, anon_verdicts=None,
               gap_findings=None, integrity_flags=None):
        """Décision agentique : le cœur décide, la couche agit et lève les doutes."""
        outputs = self.core.decide(
            threat_verdicts=threat_verdicts, anon_verdicts=anon_verdicts,
            gap_findings=gap_findings, integrity_flags=integrity_flags,
        )

        for outcome in outputs.outcomes:
            # [AGIR] exécuter les actions d'un cas confirmé
            if outcome.action_plan is not None:
                self._execute_actions(outcome)

            # [RE-SOLLICITER] tenter de lever le doute avant d'escalader
            if (outcome.decision.escalate
                    and self.config.reassess_before_escalation
                    and outcome.decision.mission.value == "investigation"):
                self._reassess_before_escalation(outcome)

        return outputs

    def _execute_actions(self, outcome):
        """[AGIS] exécuter les actions recommandées, selon la politique."""
        plan = outcome.action_plan
        host = outcome.decision.host
        for action in plan.actions:
            should = self._policy_allows(action)
            if not should:
                self.executions.append(ActionExecution(
                    action_id=action.action_id, name=action.name, host=host,
                    executed=False, reason=f"politique={self.config.policy.value} "
                                           f"→ en attente de validation humaine"))
                continue
            # exécuter via l'outil correspondant (s'il existe)
            tool = self.tools.get(action.action_id)
            if tool is not None:
                result = tool(host, {"action": action.name})
                print(f"[decision:agentique] EXÉCUTE {action.action_id} ({action.name}) "
                      f"sur {host} → {result}")
                self.executions.append(ActionExecution(
                    action_id=action.action_id, name=action.name, host=host,
                    executed=True, result=str(result)))
            else:
                self.executions.append(ActionExecution(
                    action_id=action.action_id, name=action.name, host=host,
                    executed=False, reason="aucun outil branché pour cette action"))

    def _policy_allows(self, action) -> bool:
        p = self.config.policy
        if p == ActionPolicy.MANUAL:
            return False
        if p == ActionPolicy.AUTONOMOUS:
            return True
        if p == ActionPolicy.AUTO_IMMEDIATE_ONLY:
            return getattr(action, "priority", "") == "immediate"
        return False

    def _reassess_before_escalation(self, outcome):
        """
        [PERCEPTION ACTIVE] redemander une ré-analyse avant d'escalader.

        ⚠️ UNE SEULE DEMANDE PAR HÔTE
            Avec la fenêtre de corrélation, une entité douteuse est réévaluée
            à chaque cycle tant que ses signaux restent valides. Sans cette
            mémoire, la même ré-analyse est redemandée toutes les quelques
            secondes : le journal se remplit, le compteur d'échanges gonfle,
            et Analysis — qui ne retrouve plus la séquence en cache — répond
            invariablement « pas de ré-analyse possible ».

            Redemander la même chose au même agent sans qu'aucune donnée
            nouvelle ne soit arrivée n'apporte rien : on ne le fait qu'une fois.
        """
        host = outcome.decision.host
        if not hasattr(self, "_hotes_resollicites"):
            self._hotes_resollicites = set()
        if host in self._hotes_resollicites:
            return          # déjà demandé pour cet hôte : escalade maintenue
        self._hotes_resollicites.add(host)
        if len(self._hotes_resollicites) > 500:
            self._hotes_resollicites.clear()
        print(f"[decision:agentique] cas douteux sur {host} → avant d'escalader, "
              f"je DEMANDE une ré-analyse (REANALYZE)")
        resp = self.bus.request(AgentRequest(
            request_type=RequestType.REANALYZE, sender=self.name,
            payload={"host": host, "entity_key": outcome.decision.entity_key},
        ))
        if resp and resp.success:
            new_score = resp.payload.get("attack_score")
            resolved = resp.payload.get("resolved", False)
            self.reassessments.append({
                "host": host, "reanalyzed": True,
                "new_score": new_score, "resolved": resolved,
                "detail": resp.detail,
            })
            print(f"[decision:agentique]   → ré-analyse: {resp.detail}")
            if resolved:
                # le doute est levé localement → on ANNULE l'escalade Niveau 2
                print(f"[decision:agentique]   → doute levé LOCALEMENT, "
                      f"escalade Niveau 2 ÉVITÉE")
                outcome.decision.escalate = False
                outcome.level2_dossier = None
                outcome.decision.triggered_rules.append("agentic_reassess_resolved")
        else:
            print(f"[decision:agentique]   → pas de ré-analyse possible, escalade maintenue")

    def execution_report(self) -> list[dict]:
        return [{"action_id": e.action_id, "name": e.name, "host": e.host,
                 "executed": e.executed, "result": e.result, "reason": e.reason}
                for e in self.executions]

    def reassessment_report(self) -> list[dict]:
        return self.reassessments
