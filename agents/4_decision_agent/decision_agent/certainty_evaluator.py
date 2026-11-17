# =============================================================================
# ÉVALUATEUR DE CERTITUDE — cœur décisionnel du Decision Agent
# =============================================================================
# Transforme une entité corrélée en DÉCISION, par des RÈGLES EXPLICITES
# (auditable, défendable — l'IA est réservée au générateur d'actions).
#
# Modèle à DEUX DIMENSIONS (validé par l'état de l'art SOC/SOAR — voir
# decision_agent_justification_etat_art.md) :
#
#   Dimension A — CERTITUDE / ACTION
#     CONFIRMÉ  si  menace ≥ seuil_haut               (signal fort seul)
#               ou  menace ≥ seuil_moyen + FALSIFICATION  (convergence confirmante)
#     sinon  pas d'action immédiate
#
#   Dimension B — ESCALADE NIVEAU 2 (indépendante)
#     escalade "géolocalisation"  si menace ≥ seuil_moyen + ANONYMISATION
#     escalade "investigation"    si menace ambiguë (bas..moyen) sans corroboration
#     pas d'escalade              si falsification/gap seul (→ surveillé)
#
#   Les deux dimensions se CUMULENT : convergence maximale =
#   CONFIRMÉ + escalade géoloc (contenir ET localiser en parallèle).
#
# Fondements (asymétrie) : la FALSIFICATION est un confirmateur de haute
# confiance de l'intention malveillante ("force multiplier") ; l'ANONYMISATION
# est un signal contextuel ambigu (VPN = souvent légitime), qui n'oriente que
# corrélé à une menace.
# =============================================================================

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .decision_schema import CorrelatedEntity


class CertaintyLevel(str, Enum):
    CONFIRMED = "confirmed"      # attaque avérée → action
    DOUBTFUL = "doubtful"        # soupçon → escalade
    NORMAL = "normal"            # rien de significatif
    MONITORED = "monitored"      # signal faible (falsif/gap seul) → log, pas d'action


class EscalationMission(str, Enum):
    NONE = "none"
    GEOLOCATION = "geolocation"                 # percer l'anonymisation
    INVESTIGATION = "investigation"             # lever le doute
    GEOLOCATION_AND_INVESTIGATION = "geolocation_and_investigation"


@dataclass
class Decision:
    """Décision à deux dimensions pour une entité corrélée."""
    entity_key: str
    host: Optional[str]
    # Dimension A — certitude / action
    certainty: CertaintyLevel
    # Dimension B — escalade
    escalate: bool
    mission: EscalationMission = EscalationMission.NONE
    # traçabilité (défendabilité) : les règles qui ont produit la décision
    triggered_rules: list[str] = field(default_factory=list)
    rationale: str = ""

    @property
    def needs_actions(self) -> bool:
        """Faut-il proposer des actions à l'utilisateur ? (dimension A)"""
        return self.certainty == CertaintyLevel.CONFIRMED

    def to_dict(self) -> dict:
        return {
            "entity_key": self.entity_key,
            "host": self.host,
            "certainty": self.certainty.value,
            "escalate": self.escalate,
            "mission": self.mission.value,
            "needs_actions": self.needs_actions,
            "triggered_rules": self.triggered_rules,
            "rationale": self.rationale,
        }


@dataclass
class CertaintyConfig:
    # seuils de menace (validés comme "précision proportionnelle à la conséquence")
    threat_high: float = 0.85    # seuil d'ACTION (haut : l'action a un coût)
    threat_medium: float = 0.6   # seuil de convergence / escalade géoloc
    threat_low: float = 0.3      # seuil de soupçon (escalade investigation)
    # seuils des signaux corroborants
    anonymization_min: float = 0.7
    integrity_min: float = 0.6


class CertaintyEvaluator:
    """Évalue chaque entité corrélée → Decision (2 dimensions)."""

    def __init__(self, config: Optional[CertaintyConfig] = None):
        self.config = config or CertaintyConfig()

    def evaluate(self, entity: CorrelatedEntity) -> Decision:
        c = self.config
        threat = entity.threat_score()
        has_anon = entity.has_anonymization() and entity.max_anonymization_score() >= c.anonymization_min
        has_integrity = entity.has_integrity_issue() and \
            any(s.severity >= c.integrity_min for s in entity.integrity_signals)

        rules: list[str] = []
        certainty = CertaintyLevel.NORMAL
        escalate = False
        mission = EscalationMission.NONE

        # ================= CAS SANS MENACE =================
        if not entity.has_threat():
            if has_integrity:
                # falsification/gap SEUL : surveillé, pas d'escalade (peut être un bug)
                rules.append("R6_integrity_alone_monitored")
                return Decision(
                    entity.entity_key, entity.host,
                    certainty=CertaintyLevel.MONITORED, escalate=False,
                    mission=EscalationMission.NONE, triggered_rules=rules,
                    rationale="Anomalie d'intégrité sans menace corrélée : surveillée, non escaladée.",
                )
            # rien de significatif
            rules.append("R7_nothing_significant")
            return Decision(
                entity.entity_key, entity.host,
                certainty=CertaintyLevel.NORMAL, escalate=False,
                triggered_rules=rules, rationale="Aucun signal significatif.",
            )

        # ================= DIMENSION A — CERTITUDE / ACTION =================
        # R1 : menace très forte seule → CONFIRMÉ
        if threat >= c.threat_high:
            certainty = CertaintyLevel.CONFIRMED
            rules.append("R1_strong_threat_confirms")
        # R2 : menace moyenne + FALSIFICATION → CONFIRMÉ (convergence confirmante)
        elif threat >= c.threat_medium and has_integrity:
            certainty = CertaintyLevel.CONFIRMED
            rules.append("R2_threat_plus_tampering_confirms")
        # sinon : pas encore confirmé (candidat au doute)
        else:
            certainty = CertaintyLevel.DOUBTFUL

        # ================= DIMENSION B — ESCALADE =================
        # R3 : menace (≥ moyenne) + ANONYMISATION → escalade géoloc
        if threat >= c.threat_medium and has_anon:
            escalate = True
            mission = EscalationMission.GEOLOCATION
            rules.append("R3_threat_plus_anonymization_geoloc")

        # R4 : menace ambiguë (bas..moyen) → escalade investigation.
        # NOTE (corrigé après calibration) : une corroboration (falsification ou
        # anonymisation) RENFORCE le besoin d'investiguer, elle ne l'annule pas.
        # La version antérieure exigeait `not has_integrity and not has_anon`, ce
        # qui faisait tomber entre les mailles les cas « menace modérée +
        # falsification nette » et « menace modérée + anonymisation forte »
        # (ni confirmés, ni escaladés, ni surveillés).
        if c.threat_low <= threat < c.threat_medium:
            escalate = True
            if has_anon:
                # percer l'anonymat est un préalable à l'investigation
                mission = EscalationMission.GEOLOCATION_AND_INVESTIGATION
                rules.append("R4c_ambiguous_threat_anon_geoloc_investigation")
            else:
                mission = EscalationMission.INVESTIGATION
                rules.append("R4_ambiguous_threat_investigation")
            if has_integrity:
                rules.append("R4b_integrity_reinforces_suspicion")

        # R5 : menace moyenne + anonymisation MAIS pas confirmée → géoloc + investigation
        if (threat >= c.threat_medium and has_anon
                and certainty != CertaintyLevel.CONFIRMED):
            mission = EscalationMission.GEOLOCATION_AND_INVESTIGATION
            escalate = True
            rules.append("R5_threat_anon_not_confirmed_both")

        # cohérence du niveau de certitude si on escalade sans confirmer
        if certainty == CertaintyLevel.DOUBTFUL and not escalate:
            # menace entre moyen et haut, sans anon ni falsif : doute → investigation
            if threat >= c.threat_medium:
                escalate = True
                mission = EscalationMission.INVESTIGATION
                rules.append("R4b_medium_threat_investigation")

        rationale = self._explain(certainty, escalate, mission, threat, has_anon, has_integrity)
        return Decision(
            entity.entity_key, entity.host,
            certainty=certainty, escalate=escalate, mission=mission,
            triggered_rules=rules, rationale=rationale,
        )

    def _explain(self, certainty, escalate, mission, threat, has_anon, has_integrity) -> str:
        parts = [f"menace={threat:.2f}"]
        if has_integrity:
            parts.append("falsification présente (confirmateur)")
        if has_anon:
            parts.append("anonymisation présente (signal contextuel)")
        base = ", ".join(parts)
        act = "ACTIONS proposées" if certainty == CertaintyLevel.CONFIRMED else "pas d'action immédiate"
        esc = f"escalade Niveau 2 → {mission.value}" if escalate else "pas d'escalade"
        return f"[{base}] → {certainty.value.upper()} ({act}) ; {esc}."

    def evaluate_batch(self, entities: list[CorrelatedEntity]) -> list[Decision]:
        return [self.evaluate(e) for e in entities]
