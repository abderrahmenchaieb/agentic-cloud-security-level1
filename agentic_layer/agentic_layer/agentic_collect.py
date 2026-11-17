# =============================================================================
# COUCHE AGENTIQUE — Collect Agent
# =============================================================================
# Ajoute au Collect Agent deux capacités agentiques, SANS toucher à son cœur :
#
#   1. AUTO-ADAPTATION (perçois → décide → agis)
#      Quand il détecte une falsification sur un host, il DÉCIDE d'augmenter
#      sa vigilance sur CE host : seuil de silence plus strict (k_sigma abaissé).
#      Il resserre sa surveillance là où quelque chose cloche.
#
#   2. INTERACTION (via le bus)
#      - il RÉPOND aux requêtes CHECK_GAP ("y a-t-il un gap sur ce host ?")
#      - quand il détecte un gap, il DEMANDE une re-collecte ciblée (RECOLLECT)
#        de la fenêtre manquante (accès à la source confirmé → action réelle).
#
# C'est un wrapper agentique : il enveloppe un CollectAgent et lui donne
# perception active, décision autonome et action.
# =============================================================================

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, Callable, Any

from .agent_bus import AgentBus, AgentRequest, AgentResponse, RequestType


@dataclass
class HostVigilance:
    """État de vigilance par host (modulé par ce que l'agent observe)."""
    host: str
    level: str = "normal"                 # "normal" | "heightened"
    tampering_count: int = 0
    k_sigma: float = 4.0                   # seuil de silence (bas = plus vigilant)

    def heighten(self):
        """Resserre la surveillance : seuil de silence plus strict."""
        self.tampering_count += 1
        self.level = "heightened"
        # k_sigma abaissé → détecte des silences plus courts comme anormaux
        self.k_sigma = max(1.5, 4.0 - 0.5 * self.tampering_count)


class AgenticCollectAgent:
    """
    Wrapper agentique autour d'un CollectAgent.
    Donne au Collect : vigilance adaptative + interactions via le bus.
    """

    def __init__(self, collect_agent, bus: AgentBus,
                 recollect_source: Optional[Callable[[str, tuple], Any]] = None,
                 name: str = "collect"):
        self.core = collect_agent          # le CollectAgent existant (cœur intact)
        self.bus = bus
        self.name = name
        # fonction qui re-collecte réellement depuis la source (accès confirmé)
        self.recollect_source = recollect_source
        # état de vigilance par host
        self.vigilance: dict[str, HostVigilance] = {}
        # mémoire des gaps connus (pour répondre aux CHECK_GAP)
        self.known_gaps: dict[str, list] = {}

        # s'enregistrer comme handler des requêtes qu'il sait traiter
        bus.register(RequestType.CHECK_GAP, self.handle_check_gap, self.name)
        bus.register(RequestType.RECOLLECT, self.handle_recollect, self.name)

    # -------------------------------------------------------------------------
    # Traitement agentique d'un lot : le cœur traite, puis la couche RÉAGIT
    # -------------------------------------------------------------------------
    def process_batch(self, raws: list[dict]):
        outputs = self.core.process_batch(raws)

        # [PERÇOIS] examiner les falsifications et gaps détectés par le cœur
        self._perceive_tampering(outputs)
        self._perceive_gaps(outputs)

        return outputs

    def _perceive_tampering(self, outputs):
        """Pour chaque falsification, DÉCIDER d'augmenter la vigilance du host."""
        for e in outputs.enriched:
            has_tampering = any(a.kind in ("tampering_rule", "tampering_ml")
                                for a in e.annotations)
            if has_tampering:
                host = e.log.host
                v = self.vigilance.setdefault(host, HostVigilance(host=host))
                before = v.k_sigma
                v.heighten()   # [DÉCIDE + AGIS] resserrer la surveillance
                # appliquer le nouveau seuil au moteur de silence du cœur, pour ce host
                self._apply_vigilance(host, v)
                print(f"[collect:agentique] falsification sur {host} → vigilance "
                      f"HEIGHTENED (k_sigma {before:.1f} → {v.k_sigma:.1f})")

    def _perceive_gaps(self, outputs):
        """Pour chaque gap, mémoriser + DEMANDER une re-collecte ciblée."""
        for g in outputs.gaps:
            host = g.source_key.split(":")[0] if ":" in g.source_key else g.source_key
            self.known_gaps.setdefault(host, []).append(g)

            # [AGIS] si c'est un gap de records manquants, demander une re-collecte
            missing_range = self._extract_missing_range(g)
            if missing_range:
                print(f"[collect:agentique] gap sur {host} {missing_range} → "
                      f"je demande une RE-COLLECTE ciblée")
                self.bus.request(AgentRequest(
                    request_type=RequestType.RECOLLECT, sender=self.name,
                    payload={"host": host, "range": missing_range},
                ))

    def _apply_vigilance(self, host: str, v: HostVigilance):
        """Applique le seuil de vigilance au moteur de silence du cœur."""
        # le SilenceGapDetector du cœur porte k_sigma ; on le module.
        # (ici on le fait globalement ; une version fine garderait un k_sigma par host)
        try:
            self.core.gap_engine.silence_detector.k_sigma = v.k_sigma
        except AttributeError:
            pass  # le cœur n'expose pas ce détail : la vigilance reste au niveau wrapper

    def _extract_missing_range(self, gap) -> Optional[tuple]:
        """Extrait la plage de records manquants d'un GapFinding (si applicable)."""
        import re
        gtype = getattr(gap, "gap_type", None)
        gtype_val = getattr(gtype, "value", gtype)
        if gtype_val == "record_gap":
            # le detail contient "... entre #501 et #505"
            m = re.search(r"#(\d+)\s+et\s+#(\d+)", getattr(gap, "detail", "") or "")
            if m:
                lo, hi = int(m.group(1)), int(m.group(2))
                return (lo + 1, hi - 1)   # la plage réellement manquante
        return None

    # -------------------------------------------------------------------------
    # Handlers du bus (interaction : répondre aux autres agents)
    # -------------------------------------------------------------------------
    def handle_check_gap(self, req: AgentRequest) -> AgentResponse:
        """Un autre agent (ex Analysis) demande : y a-t-il un gap sur ce host ?"""
        host = req.payload.get("host")
        gaps = self.known_gaps.get(host, [])
        return AgentResponse(
            request_id=req.request_id, responder=self.name, success=True,
            payload={"has_gap": len(gaps) > 0,
                     "gaps": [g.detail for g in gaps]},
            detail=f"{len(gaps)} gap(s) connu(s) sur {host}",
        )

    def handle_recollect(self, req: AgentRequest) -> AgentResponse:
        """Re-collecte réelle de la fenêtre manquante (accès à la source)."""
        host = req.payload.get("host")
        rng = req.payload.get("range")
        if self.recollect_source is not None:
            result = self.recollect_source(host, rng)
            return AgentResponse(
                request_id=req.request_id, responder=self.name, success=True,
                payload={"recollected": True, "range": rng, "result": result},
                detail=f"re-collecte réelle sur {host} plage {rng}",
            )
        # pas de source branchée : on trace l'intention (mode démonstration)
        return AgentResponse(
            request_id=req.request_id, responder=self.name, success=True,
            payload={"recollected": False, "range": rng},
            detail=f"re-collecte demandée sur {host} plage {rng} (source non branchée)",
        )

    def vigilance_report(self) -> dict:
        """État de vigilance courant (pour la traçabilité / la thèse)."""
        return {h: {"level": v.level, "tampering_count": v.tampering_count,
                    "k_sigma": v.k_sigma}
                for h, v in self.vigilance.items()}
