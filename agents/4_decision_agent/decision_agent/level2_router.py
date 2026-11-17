# =============================================================================
# ROUTEUR NIVEAU 2 — prépare l'escalade vers le calcul lourd
# =============================================================================
# Pour un cas escaladé (DOUTEUX, ou CONFIRMÉ + géoloc), construit le DOSSIER
# transmis au Niveau 2 : la mission demandée + toutes les données utiles au
# calcul approfondi.
#
# Le Decision Agent ne fait PAS le calcul lourd — il le déclenche et prépare
# le paquet. La géolocalisation approximative (percer l'anonymisation) est
# ENTIÈREMENT au Niveau 2 (décidé en conception). Ici on lui transmet les
# IPs anonymisées à investiguer.
#
# Module mécanique, sans IA.
# =============================================================================

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from .decision_schema import CorrelatedEntity
from .certainty_evaluator import Decision, EscalationMission


@dataclass
class Level2Dossier:
    """Dossier transmis au Niveau 2 pour le calcul approfondi."""
    dossier_id: str
    entity_key: str
    host: Optional[str]
    mission: str                               # géoloc / investigation / les deux
    created_at: str

    # contexte de la menace (pour l'investigation)
    threat_score: float = 0.0
    hypothesis: str = ""
    techniques: list = field(default_factory=list)
    observed_artifacts: list = field(default_factory=list)

    # cibles de géolocalisation (IPs anonymisées à percer)
    anonymized_ips: list = field(default_factory=list)
    anonymization_types: list = field(default_factory=list)   # tor / vpn

    # signaux d'intégrité (contexte : effacement de traces ?)
    integrity_context: list = field(default_factory=list)

    # ce que le Niveau 2 doit tenter
    requested_computations: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "dossier_id": self.dossier_id,
            "entity_key": self.entity_key,
            "host": self.host,
            "mission": self.mission,
            "created_at": self.created_at,
            "threat_score": round(self.threat_score, 3),
            "hypothesis": self.hypothesis,
            "techniques": self.techniques,
            "observed_artifacts": self.observed_artifacts,
            "anonymized_ips": self.anonymized_ips,
            "anonymization_types": self.anonymization_types,
            "integrity_context": self.integrity_context,
            "requested_computations": self.requested_computations,
        }


class Level2Router:
    """Construit le dossier d'escalade pour le Niveau 2."""

    def route(self, entity: CorrelatedEntity, decision: Decision) -> Optional[Level2Dossier]:
        """
        Renvoie un dossier SI la décision demande une escalade, sinon None.
        """
        if not decision.escalate:
            return None

        # données de la menace
        threat = entity.threat_signal
        hypothesis = threat.detail if threat else ""
        techniques = entity.techniques()
        artifacts = entity.observed_artifacts()

        # cibles de géolocalisation : les IPs anonymisées
        anon_ips = []
        anon_types = []
        for s in entity.anonymization_signals:
            anon_ips.extend(s.ips)
            if s.detail and s.detail not in anon_types:
                anon_types.append(s.detail)

        # contexte d'intégrité
        integrity = [s.detail for s in entity.integrity_signals]

        # traduire la mission en calculs demandés au Niveau 2
        requested = self._computations_for(decision.mission, anon_ips)

        import uuid
        return Level2Dossier(
            dossier_id=f"dossier-{uuid.uuid4().hex[:8]}",
            entity_key=entity.entity_key,
            host=entity.host,
            mission=decision.mission.value,
            created_at=datetime.now(timezone.utc).isoformat(),
            threat_score=entity.threat_score(),
            hypothesis=hypothesis,
            techniques=techniques,
            observed_artifacts=artifacts,
            anonymized_ips=list(dict.fromkeys(anon_ips)),   # dédupliqué, ordre gardé
            anonymization_types=anon_types,
            integrity_context=integrity,
            requested_computations=requested,
        )

    def _computations_for(self, mission: EscalationMission, anon_ips: list) -> list[str]:
        """Traduit la mission en calculs concrets demandés au Niveau 2."""
        comps: list[str] = []
        if mission in (EscalationMission.GEOLOCATION,
                       EscalationMission.GEOLOCATION_AND_INVESTIGATION):
            if anon_ips:
                comps.append("approximate_geolocation_behind_anonymization")
                comps.append("infrastructure_correlation")   # timing, ASN, latence...
        if mission in (EscalationMission.INVESTIGATION,
                       EscalationMission.GEOLOCATION_AND_INVESTIGATION):
            comps.append("deep_llm_analysis")               # LLM lourd
            comps.append("historical_correlation")          # corrélation temporelle
        return comps
