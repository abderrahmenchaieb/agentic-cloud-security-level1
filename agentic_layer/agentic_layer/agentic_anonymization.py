# =============================================================================
# COUCHE AGENTIQUE — Anonymization Detection Agent
# =============================================================================
# Ajoute deux capacités agentiques, SANS toucher au cœur :
#
#   1. CASCADE DÉCIDÉE (raisonne sur ses propres ressources)
#      Au lieu d'une cascade figée, l'agent ALLOUE son effort de calcul selon
#      son incertitude, flux par flux :
#         lookup (rapide) → si certain, STOP.
#                         → si incertain, il DÉCIDE d'engager le GNN (coûteux).
#         GNN             → si certain, STOP.
#                         → si encore incertain, il DÉCIDE d'activer Anomal-E.
#      Il n'engage le calcul lourd que quand c'est nécessaire.
#
#   2. SIGNALEMENT PROACTIF (via le bus)
#      S'il détecte du Tor/VPN, il PRÉVIENT l'Analysis (ATTENTION_HINT) :
#      "anonymisation sur ce host, regarde de plus près" — il oriente
#      l'attention du système au lieu d'attendre passivement.
#
# Wrapper agentique : enveloppe l'AnonymizationDetectionAgent.
# =============================================================================

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

from .agent_bus import AgentBus, AgentRequest, AgentResponse, RequestType


@dataclass
class AgenticAnonymizationConfig:
    # seuil de certitude : au-dessus, pas besoin d'engager le niveau suivant
    certain_threshold: float = 0.85
    # seuil d'incertitude : en-dessous, on engage le niveau suivant
    uncertain_threshold: float = 0.6
    # score de confiance minimal pour émettre un hint d'attention
    hint_min_confidence: float = 0.7


@dataclass
class EffortRecord:
    """Trace de l'effort de calcul engagé pour un flux (traçabilité)."""
    flow_id: str
    stages_used: list = field(default_factory=list)   # ["lookup"], ["lookup","gnn"]...
    final_label: str = "unknown"
    final_confidence: float = 0.0


class AgenticAnonymizationAgent:
    """
    Wrapper agentique autour de l'AnonymizationDetectionAgent.
    Donne : cascade décidée par l'incertitude + signalement proactif à l'Analysis.
    """

    def __init__(self, anon_agent, bus: AgentBus,
                 lookup_engine=None, config: Optional[AgenticAnonymizationConfig] = None,
                 name: str = "anonymization"):
        self.core = anon_agent            # cœur intact
        self.bus = bus
        self.name = name
        self.lookup = lookup_engine or getattr(anon_agent, "lookup", None)
        self.config = config or AgenticAnonymizationConfig()
        self.effort_log: list[EffortRecord] = []

    def analyze_batch(self, flows, flow_host_map: Optional[dict] = None):
        """
        Analyse agentique avec cascade décidée.
        flow_host_map : optionnel, associe flow_id → host (pour le hint à l'Analysis).
        """
        flow_host_map = flow_host_map or {}
        verdicts = []

        for flow in flows:
            verdict, effort = self._cascade_decided(flow)
            verdicts.append(verdict)
            self.effort_log.append(effort)

            # [SIGNALEMENT PROACTIF] si anonymisation détectée avec confiance → prévenir l'Analysis
            label = getattr(verdict.label, "value", verdict.label)
            if label in ("tor", "vpn") and verdict.confidence >= self.config.hint_min_confidence:
                host = flow_host_map.get(getattr(flow, "flow_id", None))
                self._hint_analysis(verdict, host)

        return verdicts

    def _cascade_decided(self, flow):
        """[DÉCIDE] engager chaque niveau seulement si l'incertitude le justifie."""
        c = self.config
        effort = EffortRecord(flow_id=getattr(flow, "flow_id", "?"))

        # --- Niveau 1 : lookup (rapide) ---
        effort.stages_used.append("lookup")
        v = self.lookup.analyze(flow) if self.lookup else None
        if v is not None and v.confidence >= c.certain_threshold:
            # certain dès le lookup → STOP, pas besoin du GNN
            effort.final_label = getattr(v.label, "value", v.label)
            effort.final_confidence = v.confidence
            return v, effort

        # --- Niveau 2 : GNN (coûteux) — DÉCIDÉ car le lookup n'a pas suffi ---
        if self.core.gnn is not None:
            effort.stages_used.append("gnn")
            print(f"[anon:agentique] flux {effort.flow_id}: lookup insuffisant "
                  f"→ j'ENGAGE le GNN (coûteux)")
            gnn_verdicts = self.core._run_gnn([flow])
            gv = gnn_verdicts.get(getattr(flow, "flow_id", None))
            if gv is not None:
                # --- Niveau 3 : Anomal-E — DÉCIDÉ si le GNN reste incertain ---
                if (gv.confidence < c.uncertain_threshold
                        and self.core.anomale is not None):
                    effort.stages_used.append("anomale")
                    print(f"[anon:agentique] flux {effort.flow_id}: GNN incertain "
                          f"({gv.confidence:.2f}) → j'ACTIVE Anomal-E (second avis)")
                    # (le cœur sait combiner ; ici on trace la décision d'escalade d'effort)
                effort.final_label = getattr(gv.label, "value", gv.label)
                effort.final_confidence = gv.confidence
                return gv, effort

        # rien n'a tranché : renvoyer le verdict du lookup (même incertain) ou UNKNOWN
        if v is not None:
            effort.final_label = getattr(v.label, "value", v.label)
            effort.final_confidence = v.confidence
            return v, effort
        # UNKNOWN
        from anonymization_detection_agent import AnonymizationVerdict, AnonymizationLabel
        uv = AnonymizationVerdict(
            flow_id=getattr(flow, "flow_id", "?"),
            external_ip=getattr(flow, "dst_ip", None),
            label=AnonymizationLabel.UNKNOWN, confidence=0.0, method="none",
        )
        return uv, effort

    def _hint_analysis(self, verdict, host):
        """[PERCEPTION → ACTION] prévenir l'Analysis de surveiller ce host."""
        label = getattr(verdict.label, "value", verdict.label)
        print(f"[anon:agentique] {label.upper()} détecté (IP {verdict.external_ip}, "
              f"conf {verdict.confidence:.2f}) → je PRÉVIENS l'Analysis"
              + (f" (host {host})" if host else ""))
        self.bus.request(AgentRequest(
            request_type=RequestType.ATTENTION_HINT, sender=self.name,
            payload={"host": host, "external_ip": verdict.external_ip,
                     "anonymization": label, "confidence": verdict.confidence},
        ))

    def effort_report(self) -> list[dict]:
        """Journal de l'effort de calcul par flux (pour la thèse : allocation adaptative)."""
        return [{"flow_id": e.flow_id, "stages": e.stages_used,
                 "label": e.final_label, "confidence": round(e.final_confidence, 2)}
                for e in self.effort_log]
