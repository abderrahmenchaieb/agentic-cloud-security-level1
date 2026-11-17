# =============================================================================
# RÈGLES FORENSIQUES DE DÉTECTION DE FALSIFICATION
# =============================================================================
# Détecte les traces de MANIPULATION des logs (tampering), pas les attaques.
# Approche par RÈGLES déterministes, haute fidélité : chaque règle repère une
# incohérence qui NE DEVRAIT PAS exister dans des logs authentiques.
#
# Ces règles couvrent les falsifications CONNUES. Le ML (brique suivante)
# couvrira les falsifications INATTENDUES.
#
# Les 4 types de falsification (littérature) :
#   - MODIFICATION  : altérer un champ (ex : timestamp "stompé")
#   - SUPPRESSION   : retirer des logs (→ détecté via les gaps, autre brique)
#   - RÉORDONNANCEMENT : casser l'ordre chronologique
#   - INJECTION     : insérer de faux logs
# =============================================================================

from __future__ import annotations
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass
from enum import Enum
from typing import Optional
from .canonical_schema import CanonicalLog, ActivityCategory


class TamperType(str, Enum):
    TIMESTAMP_ANOMALY = "timestamp_anomaly"        # modification (timestomping)
    SEQUENCE_ANOMALY = "sequence_anomaly"          # réordonnancement
    FILIATION_ANOMALY = "filiation_anomaly"        # injection (parent impossible)
    CLOCK_SKEW_ANOMALY = "clock_skew_anomaly"      # écart ingest/event anormal
    IMPOSSIBLE_VALUE = "impossible_value"          # valeur qui ne peut pas exister
    TIME_CHANGE = "time_change"                    # changement d'heure système (4616)
    LOG_DELETION = "log_deletion"                  # effacement de journal (1102/104)
    LOGGING_DISABLED = "logging_disabled"          # service Event Log arrêté (1100)
    SELECTIVE_DELETION = "selective_deletion"      # trous dans les record-ID


@dataclass
class TamperFinding:
    """Un signalement de falsification produit par une règle."""
    tamper_type: TamperType
    rule_id: str
    confidence: str          # "high" (règle déterministe) — le ML fera du "medium"
    detail: str
    event_id: str


# -----------------------------------------------------------------------------
# BORNES DE PLAUSIBILITÉ
# -----------------------------------------------------------------------------
# Époque minimale plausible pour un log (avant = timestamp "stompé")
MIN_PLAUSIBLE_TIME = datetime(2000, 1, 1, tzinfo=timezone.utc)
# Tolérance de clock skew (event_time vs ingest_time) au-delà de laquelle c'est suspect
MAX_CLOCK_SKEW = timedelta(hours=24)

# Process légitimes autorisés à changer l'heure système (synchro NTP / VM).
# Validé sur COMISET : vmtoolsd.exe génère des changements d'heure BÉNINS (resynchro VM).
PROCESS_TEMPS_LEGITIMES = {
    "vmtoolsd.exe",       # VMware Tools (synchro VM)
    "svchost.exe",        # W32Time (service de temps Windows)
    "vboxservice.exe",    # VirtualBox Guest Additions
    "systemsettings.exe", # réglage manuel via l'UI Windows
    "vmwaretray.exe",
}
# Seuil de trou dans les record-ID au-delà duquel on suspecte une suppression sélective
MAX_RECORD_GAP = 100


# =============================================================================
# RÈGLES SUR UN LOG ISOLÉ (stateless)
# =============================================================================

def rule_timestomping(log: CanonicalLog) -> Optional[TamperFinding]:
    """
    R1 — Timestomping : un timestamp antérieur à une époque plausible
    (ex : 1970, 1601) trahit une altération. Technique anti-forensique classique.
    """
    if log.event_time < MIN_PLAUSIBLE_TIME:
        return TamperFinding(
            tamper_type=TamperType.TIMESTAMP_ANOMALY,
            rule_id="R1_timestomping",
            confidence="high",
            detail=f"event_time {log.event_time.isoformat()} antérieur à l'époque plausible",
            event_id=log.event_id,
        )
    return None


def rule_future_timestamp(log: CanonicalLog) -> Optional[TamperFinding]:
    """
    R2 — Timestamp dans le futur : un event_time nettement postérieur à
    l'ingestion est impossible pour un log authentique (le log ne peut pas
    décrire un événement futur).
    """
    if log.event_time > log.ingest_time + timedelta(minutes=5):
        return TamperFinding(
            tamper_type=TamperType.TIMESTAMP_ANOMALY,
            rule_id="R2_future_timestamp",
            confidence="high",
            detail=f"event_time ({log.event_time.isoformat()}) dans le futur vs ingest",
            event_id=log.event_id,
        )
    return None


def rule_clock_skew(log: CanonicalLog) -> Optional[TamperFinding]:
    """
    R3 — Clock skew anormal : un écart énorme entre event_time et ingest_time
    peut indiquer une injection tardive de faux logs ou une manipulation d'horloge.
    """
    if log.clock_skew_seconds() > MAX_CLOCK_SKEW.total_seconds():
        return TamperFinding(
            tamper_type=TamperType.CLOCK_SKEW_ANOMALY,
            rule_id="R3_clock_skew",
            confidence="high",
            detail=f"clock skew de {log.clock_skew_seconds():.0f}s (> {MAX_CLOCK_SKEW})",
            event_id=log.event_id,
        )
    return None


def rule_self_parent(log: CanonicalLog) -> Optional[TamperFinding]:
    """
    R4 — Filiation impossible : un processus qui est son propre parent
    (guid == parent_guid) est structurellement impossible → injection.
    """
    pc = log.process_context
    if pc and pc.process_guid and pc.process_guid == pc.parent_process_guid:
        return TamperFinding(
            tamper_type=TamperType.FILIATION_ANOMALY,
            rule_id="R4_self_parent",
            confidence="high",
            detail=f"process_guid == parent_process_guid ({pc.process_guid})",
            event_id=log.event_id,
        )
    return None


STATELESS_RULES = [rule_timestomping, rule_future_timestamp, rule_clock_skew, rule_self_parent]


# =============================================================================
# RÈGLES SUR UN FLUX ORDONNÉ (stateful — détecte réordonnancement)
# =============================================================================

class SequenceIntegrityChecker:
    """
    R5 — Réordonnancement : dans un flux de logs d'une même source, les
    event_time doivent être monotones croissants (à la tolérance près).
    Un recul temporel = possible réordonnancement / injection.

    État par source (les logs d'une même source arrivent ordonnés).
    """
    def __init__(self, tolerance_seconds: float = 1.0):
        self.tolerance = tolerance_seconds
        self._last_time: dict[str, datetime] = {}  # source_provider -> dernier event_time

    def check(self, log: CanonicalLog) -> Optional[TamperFinding]:
        key = f"{log.host}:{log.source_provider}"
        last = self._last_time.get(key)
        self._last_time[key] = log.event_time

        if last is not None and log.event_time < last - timedelta(seconds=self.tolerance):
            return TamperFinding(
                tamper_type=TamperType.SEQUENCE_ANOMALY,
                rule_id="R5_out_of_order",
                confidence="high",
                detail=f"event_time {log.event_time.isoformat()} < précédent {last.isoformat()}",
                event_id=log.event_id,
            )
        return None


# =============================================================================
# RÈGLES FORENSIQUES ENRICHIES (signaux anti-forensiques documentés)
# Fondées sur la littérature 2026 et validées sur COMISET.
# Les champs Windows spécifiques (PreviousTime, provider, record_number) sont
# lus depuis log.extra, alimenté par le mapper à l'ingestion.
# =============================================================================

def rule_time_change(log: CanonicalLog) -> Optional[TamperFinding]:
    """
    R6 — Changement d'heure système (Event 4616) par un process NON légitime.
    Un attaquant peut changer l'horloge pour fausser la timeline (anti-forensique).
    Distingue la synchro légitime (VMware/NTP) de la manipulation, via le process.
    """
    if log.extra.get("windows_event_id") != "4616":
        return None
    pname = str(log.extra.get("time_change_process", "")).lower().split("\\")[-1]
    if pname in PROCESS_TEMPS_LEGITIMES:
        return None  # synchro NTP/VM bénigne
    # ampleur du saut d'heure
    saut = 0.0
    try:
        pt = datetime.fromisoformat(str(log.extra.get("previous_time", "")).replace("Z", "+00:00").replace("\u200e", ""))
        nt = datetime.fromisoformat(str(log.extra.get("new_time", "")).replace("Z", "+00:00").replace("\u200e", ""))
        saut = abs((nt - pt).total_seconds())
    except Exception:
        pass
    return TamperFinding(
        tamper_type=TamperType.TIME_CHANGE,
        rule_id="R6_time_change",
        confidence="high" if saut > 3600 else "medium",
        detail=f"changement d'heure par '{pname}' (saut {saut:.0f}s) — anti-forensique probable",
        event_id=log.event_id,
    )


def rule_log_cleared(log: CanonicalLog) -> Optional[TamperFinding]:
    """
    R7 — Effacement de journal (Event 1102 = Security, 104 = System cleared).
    Signal FORT : un attaquant efface les traces. Haute confiance.
    """
    eid = log.extra.get("windows_event_id")
    provider = str(log.extra.get("windows_provider", "")).lower()
    if eid == "1102":
        return TamperFinding(
            tamper_type=TamperType.LOG_DELETION, rule_id="R7_log_cleared",
            confidence="high", detail="journal de sécurité effacé (Event 1102)",
            event_id=log.event_id)
    if eid == "104" and "eventlog" in provider:
        return TamperFinding(
            tamper_type=TamperType.LOG_DELETION, rule_id="R7_log_cleared",
            confidence="high", detail="journal effacé (Event 104)",
            event_id=log.event_id)
    return None


def rule_eventlog_stopped(log: CanonicalLog) -> Optional[TamperFinding]:
    """
    R8 — Arrêt du service Event Log (Event 1100).
    Un attaquant coupe la journalisation pour ne plus être tracé.
    """
    if log.extra.get("windows_event_id") == "1100":
        return TamperFinding(
            tamper_type=TamperType.LOGGING_DISABLED, rule_id="R8_eventlog_stopped",
            confidence="medium", detail="service Event Log arrêté (Event 1100)",
            event_id=log.event_id)
    return None


STATELESS_RULES_ENRICHIES = [rule_time_change, rule_log_cleared, rule_eventlog_stopped]


class RecordGapChecker:
    """
    R9 — Trous dans les record-ID (suppression sélective d'événements).
    Suit les record_number par source ; un trou anormal trahit une suppression.
    """
    def __init__(self, max_gap: int = MAX_RECORD_GAP):
        self.max_gap = max_gap
        self._last_record: dict[str, int] = {}

    def check(self, log: CanonicalLog) -> Optional[TamperFinding]:
        rn = log.extra.get("record_number")
        if rn is None or not str(rn).isdigit():
            return None
        rn = int(rn)
        key = log.host or "default"
        last = self._last_record.get(key)
        self._last_record[key] = rn
        if last is not None and rn - last > self.max_gap:
            return TamperFinding(
                tamper_type=TamperType.SELECTIVE_DELETION, rule_id="R9_record_gap",
                confidence="medium",
                detail=f"trou dans les record-ID ({last}→{rn}, ~{rn-last} événements manquants)",
                event_id=log.event_id)
        return None


# =============================================================================
# ORCHESTRATEUR
# =============================================================================

class ForensicRuleEngine:
    """Applique toutes les règles forensiques à un log."""
    def __init__(self):
        self.sequence_checker = SequenceIntegrityChecker()
        self.record_gap_checker = RecordGapChecker()

    def analyze(self, log: CanonicalLog) -> list[TamperFinding]:
        findings: list[TamperFinding] = []
        # règles sur log isolé (R1-R4)
        for rule in STATELESS_RULES:
            f = rule(log)
            if f:
                findings.append(f)
        # règles enrichies sur log isolé (R6-R8 : signaux anti-forensiques)
        for rule in STATELESS_RULES_ENRICHIES:
            f = rule(log)
            if f:
                findings.append(f)
        # règle sur le flux ordonné (R5 out-of-order)
        f = self.sequence_checker.check(log)
        if f:
            findings.append(f)
        # règle sur les trous de record-ID (R9)
        f = self.record_gap_checker.check(log)
        if f:
            findings.append(f)
        return findings
