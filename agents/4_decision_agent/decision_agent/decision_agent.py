# =============================================================================
# DECISION AGENT — assemblage complet
# =============================================================================
# Frontière Niveau 1 / Niveau 2. Corrèle les signaux des trois agents, évalue
# la certitude, et produit un DOUBLE flux de sortie :
#
#   signaux (Analysis + Anonymization + Collect)
#        │
#        ▼  [1] NORMALISATION → signaux communs
#        ▼  [2] CORRÉLATION → entités (menace + anon par IP + intégrité par host)
#        ▼  [3] ÉVALUATION DE CERTITUDE → décision (2 dimensions)
#        │
#        ├─ CONFIRMÉ ─► [4] GÉNÉRATEUR D'ACTIONS (LLM+D3FEND) ─► actions à l'user
#        │
#        └─ ESCALADÉ ─► [5] ROUTEUR NIVEAU 2 ─► dossier (géoloc / investigation)
#
#   (les deux peuvent se produire EN PARALLÈLE : contenir ET localiser)
#
# Décide sans Niveau 2 quand c'est clair ; escalade quand il y a doute ou
# anonymisation à percer.
# =============================================================================

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

from .decision_schema import CorrelatedEntity
from .signal_normalizers import normalize_all
from .correlator import Correlator, CorrelatorConfig
from .certainty_evaluator import CertaintyEvaluator, CertaintyConfig, Decision, CertaintyLevel
from .action_generator import ActionGenerator, ActionPlan
from .level2_router import Level2Router, Level2Dossier


@dataclass
class EntityOutcome:
    """Résultat complet pour une entité : décision + éventuels actions/dossier."""
    entity: CorrelatedEntity
    decision: Decision
    action_plan: Optional[ActionPlan] = None       # si CONFIRMÉ
    level2_dossier: Optional[Level2Dossier] = None  # si escaladé

    def to_dict(self) -> dict:
        return {
            "decision": self.decision.to_dict(),
            "action_plan": self.action_plan.to_dict() if self.action_plan else None,
            "level2_dossier": self.level2_dossier.to_dict() if self.level2_dossier else None,
        }


@dataclass
class DecisionOutputs:
    outcomes: list[EntityOutcome] = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    def confirmed(self) -> list[EntityOutcome]:
        return [o for o in self.outcomes if o.decision.certainty == CertaintyLevel.CONFIRMED]

    def escalated(self) -> list[EntityOutcome]:
        return [o for o in self.outcomes if o.decision.escalate]

    def action_plans(self) -> list[ActionPlan]:
        return [o.action_plan for o in self.outcomes if o.action_plan]

    def level2_dossiers(self) -> list[Level2Dossier]:
        return [o.level2_dossier for o in self.outcomes if o.level2_dossier]


class DecisionAgent:
    """
    Agent de décision : corrèle, évalue, et route (actions ou Niveau 2).
    Le générateur d'actions (LLM) est OPTIONNEL : sans lui, l'agent décide et
    escalade, mais ne formule pas les actions en langage naturel.
    """

    def __init__(self,
                 action_generator: Optional[ActionGenerator] = None,
                 correlator: Optional[Correlator] = None,
                 evaluator: Optional[CertaintyEvaluator] = None,
                 router: Optional[Level2Router] = None):
        self.correlator = correlator or Correlator()
        self.evaluator = evaluator or CertaintyEvaluator()
        self.action_generator = action_generator     # None = pas de formulation LLM
        self.router = router or Level2Router()

    def decide(self,
               threat_verdicts: list = None,
               anon_verdicts: list = None,
               gap_findings: list = None,
               integrity_flags: list = None) -> DecisionOutputs:
        outputs = DecisionOutputs()

        # [1] Normalisation
        signals = normalize_all(
            threat_verdicts=threat_verdicts, anon_verdicts=anon_verdicts,
            gap_findings=gap_findings, integrity_flags=integrity_flags,
        )

        # [2] Corrélation
        entities = self.correlator.correlate(signals)

        n_confirmed = n_escalated = n_actions = 0

        for entity in entities:
            # [3] Évaluation de certitude
            decision = self.evaluator.evaluate(entity)
            outcome = EntityOutcome(entity=entity, decision=decision)

            # [4] Générateur d'actions (si CONFIRMÉ)
            if decision.certainty == CertaintyLevel.CONFIRMED:
                n_confirmed += 1
                if self.action_generator is not None:
                    techniques = [t.get("id") if isinstance(t, dict) else getattr(t, "technique_id", None)
                                  for t in entity.techniques()]
                    techniques = [t for t in techniques if t]
                    hypothesis = entity.threat_signal.detail if entity.threat_signal else ""
                    outcome.action_plan = self.action_generator.generate(
                        entity.entity_key, entity.host, hypothesis, techniques,
                        observed_artifacts=entity.observed_artifacts(),
                    )
                    n_actions += 1

            # [5] Routeur Niveau 2 (si escaladé) — PEUT coexister avec les actions
            if decision.escalate:
                n_escalated += 1
                outcome.level2_dossier = self.router.route(entity, decision)

            outputs.outcomes.append(outcome)

        outputs.stats = {
            "n_entities": len(entities),
            "n_confirmed": n_confirmed,
            "n_escalated": n_escalated,
            "n_action_plans": n_actions,
        }
        return outputs
