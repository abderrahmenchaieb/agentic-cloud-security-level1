# =============================================================================
# COLLECT AGENT — assemblage complet
# =============================================================================
# Orchestre toutes les briques en un pipeline cohérent :
#
#   log brut Sysmon
#        │
#        ▼  [1] mapper → canonique + détection MALFORMÉS
#        │        └── malformé → rejected_logs (STOP)
#        ▼  [2] règles forensiques → FALSIFICATION (connue)
#        ▼  [3] détection de GAPS → suppression
#        ▼  [4] ML d'anomalie → FALSIFICATION (inattendue)
#        │
#        ▼  routage des sorties :
#        ├── enriched  (log + annotations d'intégrité)  → Analysis Agent
#        ├── flows     (si événement réseau)            → Geolocation Agent
#        ├── gaps      (signalements de données manquantes) → Analysis Agent
#        └── rejected  (malformés)                       → audit
#
# Principe : SIGNALE, ne décide pas. Ne supprime jamais silencieusement.
# =============================================================================

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional, Any

from .canonical_schema import CanonicalLog, ActivityCategory
from .sysmon_mapper import map_sysmon_event
from .forensic_rules import ForensicRuleEngine, TamperFinding
from .gap_detection import GapDetectionEngine, GapFinding
from .anomaly_ml import AnomalyDetector, AnomalyFinding


# -----------------------------------------------------------------------------
# Structures de sortie
# -----------------------------------------------------------------------------

@dataclass
class IntegrityAnnotation:
    """Une annotation d'intégrité attachée à un log."""
    kind: str                    # "tampering_rule" | "tampering_ml" | "gap"
    confidence: str              # "high" (règle) | "medium" (ML)
    detail: str
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class EnrichedLog:
    """Sortie principale : un log valide + ses annotations d'intégrité."""
    log: CanonicalLog
    annotations: list[IntegrityAnnotation] = field(default_factory=list)

    @property
    def has_integrity_issue(self) -> bool:
        return len(self.annotations) > 0


@dataclass
class FlowRecord:
    """Sortie vers le Geolocation Agent (métadonnées réseau)."""
    event_id: str
    source_ip: Optional[str]
    destination_ip: Optional[str]
    destination_port: Optional[int]
    protocol: Optional[str]
    event_time: str


@dataclass
class RejectedLog:
    """Log malformé écarté (tracé, jamais supprimé silencieusement)."""
    raw: dict
    reason: str
    rejected_at: str


@dataclass
class CollectOutputs:
    """Les 4 canaux de sortie du Collect Agent."""
    enriched: list[EnrichedLog] = field(default_factory=list)
    flows: list[FlowRecord] = field(default_factory=list)
    gaps: list[GapFinding] = field(default_factory=list)
    rejected: list[RejectedLog] = field(default_factory=list)

    def summary(self) -> dict:
        n_flagged = sum(1 for e in self.enriched if e.has_integrity_issue)
        return {
            "enriched_total": len(self.enriched),
            "enriched_flagged": n_flagged,
            "flows": len(self.flows),
            "gaps": len(self.gaps),
            "rejected": len(self.rejected),
        }


# -----------------------------------------------------------------------------
# Le Collect Agent
# -----------------------------------------------------------------------------

class CollectAgent:
    """
    Agent de collecte : orchestre mapping, intégrité, gaps et ML.
    Le ML est OPTIONNEL (activable une fois entraîné sur un corpus intègre).
    """

    def __init__(self, anomaly_detector: Optional[AnomalyDetector] = None,
                 ml_threshold: Optional[float] = None,
                 replay_mode: bool = False):
        # replay_mode : pour REJOUER un corpus historique. En temps réel,
        # l'écart event_time / ingest_time mesure une vraie dérive d'horloge
        # (règle R3). Sur un dataset vieux de plusieurs années, cet écart
        # atteint des centaines de jours et R3 se déclenche sur CHAQUE
        # événement. Voir map_sysmon_event(replay_mode=...).
        self.replay_mode = replay_mode
        self.forensic_engine = ForensicRuleEngine()
        self.gap_engine = GapDetectionEngine()
        self.anomaly_detector = anomaly_detector   # None = ML désactivé
        self.ml_threshold = ml_threshold           # seuil calibré sur le normal
        self.outputs = CollectOutputs()
        # compteurs de santé (pour l'auto-surveillance de l'agent)
        self.stats = {"processed": 0, "malformed": 0, "tampering": 0, "gaps": 0}

    def _source_key(self, log: CanonicalLog) -> str:
        return f"{log.host}:{log.source_provider}"

    def process(self, raw: dict) -> None:
        """Traite UN log brut Sysmon à travers tout le pipeline."""
        self.stats["processed"] += 1

        # --- [1] Mapping + détection de malformés ---
        result = map_sysmon_event(raw, replay_mode=self.replay_mode)
        if not result.is_valid:
            self.stats["malformed"] += 1
            self.outputs.rejected.append(RejectedLog(
                raw=raw,
                reason=result.rejection_reason or "unknown",
                rejected_at=datetime.now(timezone.utc).isoformat(),
            ))
            return  # un malformé ne va pas plus loin (mais il est tracé)

        log = result.log
        annotations: list[IntegrityAnnotation] = []

        # --- [2] Règles forensiques (falsification connue) ---
        tamper_findings: list[TamperFinding] = self.forensic_engine.analyze(log)
        for tf in tamper_findings:
            self.stats["tampering"] += 1
            annotations.append(IntegrityAnnotation(
                kind="tampering_rule",
                confidence=tf.confidence,
                detail=f"[{tf.rule_id}] {tf.detail}",
                extra={"tamper_type": tf.tamper_type.value},
            ))

        # --- [3] Détection de gaps (suppression) ---
        gap_findings = self.gap_engine.analyze_log(
            self._source_key(log), log.raw_ref and _safe_int(log.raw_ref), log.event_time
        )
        for gf in gap_findings:
            self.stats["gaps"] += 1
            self.outputs.gaps.append(gf)
            annotations.append(IntegrityAnnotation(
                kind="gap",
                confidence="high",
                detail=gf.detail,
                extra={"gap_type": gf.gap_type.value, "severity": gf.severity_score},
            ))

        # --- [4] ML d'anomalie (falsification inattendue) — si activé ---
        if self.anomaly_detector is not None and self.ml_threshold is not None:
            finding: AnomalyFinding = self.anomaly_detector.score(log)
            if finding.raw_score < self.ml_threshold:  # plus bas = plus anormal
                annotations.append(IntegrityAnnotation(
                    kind="tampering_ml",
                    confidence="medium",
                    detail=f"anomalie ML (score {finding.raw_score:.3f})",
                    extra={"top_features": finding.top_features},
                ))

        # --- Routage : sortie enriched (tous les logs valides) ---
        self.outputs.enriched.append(EnrichedLog(log=log, annotations=annotations))

        # --- Routage : sortie flows (si événement réseau) ---
        if log.activity == ActivityCategory.NETWORK_CONNECTION and log.target:
            self.outputs.flows.append(FlowRecord(
                event_id=log.event_id,
                source_ip=log.actor.source_ip if log.actor else None,
                destination_ip=log.target.destination_ip,
                destination_port=log.target.destination_port,
                protocol=log.target.protocol,
                event_time=log.event_time.isoformat(),
            ))

    def process_batch(self, raws: list[dict]) -> CollectOutputs:
        for raw in raws:
            self.process(raw)
        return self.outputs

    def check_source_health(self, now: Optional[datetime] = None) -> list[GapFinding]:
        """Vérification périodique : une source s'est-elle tue ? (auto-surveillance)"""
        now = now or datetime.now(timezone.utc)
        silence_gaps = self.gap_engine.check_silence(now)
        for gf in silence_gaps:
            self.outputs.gaps.append(gf)
        return silence_gaps


def _safe_int(v: Any) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None
