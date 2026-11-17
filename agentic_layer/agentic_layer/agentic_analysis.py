# =============================================================================
# COUCHE AGENTIQUE — Analysis Agent
# =============================================================================
# Ajoute à l'Analysis Agent deux capacités agentiques, SANS toucher à son cœur :
#
#   1. AUTO-APPROFONDISSEMENT (décide de sa propre stratégie)
#      Quand le score ML est dans une ZONE D'INCERTITUDE (ni clairement attaque
#      ni clairement normal), l'agent DÉCIDE de creuser : il relance l'analyse
#      avec merge_by_session activé (pour rattraper une attaque qui a cassé la
#      filiation de processus). Il choisit de creuser au lieu d'un verdict tiède.
#
#   2. COOPÉRATION (via le bus)
#      Quand une séquence suspecte semble INCOMPLÈTE (chaîne coupée), l'agent
#      DEMANDE au Collect : "y a-t-il eu un gap sur ce host ?" (CHECK_GAP).
#      Si oui → l'incomplétude s'explique par une suppression de logs, il RELÈVE
#      sa suspicion. Deux agents coopèrent pour comprendre.
#
# Wrapper agentique : enveloppe un AnalysisAgent, lui donne décision autonome
# sur sa stratégie et perception active via le bus.
# =============================================================================

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

from .agent_bus import AgentBus, AgentRequest, AgentResponse, RequestType


@dataclass
class AgenticAnalysisConfig:
    # zone d'incertitude du score : ni clairement normal, ni clairement attaque
    uncertain_low: float = 0.30
    uncertain_high: float = 0.60
    # une séquence est jugée "incomplète" si elle a peu d'événements
    # alors qu'elle montre des signes d'attaque (chaîne probablement coupée)
    incomplete_max_events: int = 3
    # de combien relever le score quand un gap explique l'incomplétude
    gap_suspicion_boost: float = 0.25


class AgenticAnalysisAgent:
    """
    Wrapper agentique autour d'un AnalysisAgent.
    Donne : auto-approfondissement (merge_by_session) + coopération avec le Collect.
    """

    def __init__(self, analysis_agent, bus: AgentBus,
                 builder_cls=None, builder_config_cls=None,
                 config: Optional[AgenticAnalysisConfig] = None,
                 name: str = "analysis"):
        self.core = analysis_agent          # AnalysisAgent existant (cœur intact)
        self.bus = bus
        self.name = name
        self.config = config or AgenticAnalysisConfig()
        # classes du builder (pour reconstruire un builder approfondi si besoin)
        self._builder_cls = builder_cls
        self._builder_config_cls = builder_config_cls
        # journal des décisions agentiques (traçabilité)
        self.decisions: list[dict] = []

    def analyze(self, events):
        """Analyse agentique : le cœur analyse, la couche décide d'approfondir/coopérer."""
        outputs = self.core.analyze(events)

        # [PERÇOIS] parcourir les verdicts, réagir aux cas incertains/incomplets
        for verdict in outputs.verdicts:
            self._react(verdict, events)

        return outputs

    def _react(self, verdict, events):
        score = verdict.attack_score
        c = self.config
        summary = verdict.sequence_summary or {}
        n_events = summary.get("n_events", 0)

        # ---- CAS 1 : score dans la zone d'incertitude → APPROFONDIR ----
        if c.uncertain_low <= score < c.uncertain_high and not verdict.is_attack:
            self._deepen(verdict, events)

        # ---- CAS 2 : séquence suspecte mais incomplète → DEMANDER au Collect ----
        looks_incomplete = (n_events <= c.incomplete_max_events
                            and score >= c.uncertain_low)
        if looks_incomplete:
            self._ask_collect_about_gap(verdict)

    def _deepen(self, verdict, events):
        """[DÉCIDE + AGIS] relancer l'analyse avec merge_by_session activé."""
        if self._builder_cls is None or self._builder_config_cls is None:
            return  # pas de quoi reconstruire un builder : on trace l'intention
        print(f"[analysis:agentique] score={verdict.attack_score:.2f} incertain sur "
              f"{verdict.host} → j'APPROFONDIS (merge_by_session)")
        # construire un builder plus agressif (fusion par session)
        deep_builder = self._builder_cls(
            self._builder_config_cls(merge_by_session=True))
        # réanalyser SEULEMENT en reconstruisant les séquences autrement
        deep_sequences = deep_builder.build(events)
        # re-détecter sur les séquences fusionnées
        best_score = verdict.attack_score
        for seq in deep_sequences:
            if seq.host != verdict.host:
                continue
            det = self.core.detector.predict(seq)
            best_score = max(best_score, det.attack_score)
        improved = best_score > verdict.attack_score
        self.decisions.append({
            "host": verdict.host, "action": "deepen_merge_by_session",
            "score_before": round(verdict.attack_score, 3),
            "score_after": round(best_score, 3), "improved": improved,
        })
        if improved:
            print(f"[analysis:agentique]   → approfondissement PAYANT : "
                  f"score {verdict.attack_score:.2f} → {best_score:.2f}")
            verdict.attack_score = best_score
            if best_score >= self.config.uncertain_high:
                verdict.is_attack = True

    def _ask_collect_about_gap(self, verdict):
        """[PERCEPTION ACTIVE] demander au Collect s'il y a un gap sur ce host."""
        print(f"[analysis:agentique] séquence incomplète sur {verdict.host} "
              f"(score {verdict.attack_score:.2f}) → je demande au Collect : gap ?")
        resp = self.bus.request(AgentRequest(
            request_type=RequestType.CHECK_GAP, sender=self.name,
            payload={"host": verdict.host},
        ))
        if resp and resp.payload.get("has_gap"):
            gaps = resp.payload.get("gaps", [])
            boost = self.config.gap_suspicion_boost
            new_score = min(1.0, verdict.attack_score + boost)
            print(f"[analysis:agentique]   → le Collect confirme un gap : {gaps}")
            print(f"[analysis:agentique]   → l'incomplétude s'explique (logs supprimés), "
                  f"je RELÈVE la suspicion : {verdict.attack_score:.2f} → {new_score:.2f}")
            self.decisions.append({
                "host": verdict.host, "action": "raise_on_gap",
                "score_before": round(verdict.attack_score, 3),
                "score_after": round(new_score, 3), "gap_detail": gaps,
            })
            verdict.attack_score = new_score
            # ajouter un flag explicatif au verdict
            if hasattr(verdict, "integrity_flags"):
                verdict.integrity_flags = list(verdict.integrity_flags) + \
                    [f"[coopération] gap confirmé par Collect: {g}" for g in gaps]
            if new_score >= self.config.uncertain_high:
                verdict.is_attack = True
        else:
            print(f"[analysis:agentique]   → pas de gap : l'incomplétude reste inexpliquée")

    def decisions_report(self) -> list[dict]:
        """Journal des décisions agentiques (pour la thèse)."""
        return self.decisions
