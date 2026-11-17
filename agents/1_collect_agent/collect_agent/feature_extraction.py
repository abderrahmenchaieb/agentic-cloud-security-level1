# =============================================================================
# EXTRACTION DE FEATURES — pour le ML d'anomalie du Collect Agent
# =============================================================================
# Transforme un CanonicalLog en vecteur numérique exploitable par un modèle
# d'anomalie non-supervisé (Isolation Forest).
#
# Objectif : capturer des caractéristiques d'INTÉGRITÉ (pas d'attaque).
# Le ML apprend à quoi ressemble un log "normal" sur ces features, puis
# signale les logs qui dévient — y compris des falsifications INATTENDUES
# que les règles ne couvrent pas.
#
# Les features sont pensées pour être sensibles à la MANIPULATION :
# incohérences temporelles, structurelles, statistiques.
# =============================================================================

from __future__ import annotations
from datetime import timezone
import math
from typing import Optional
from .canonical_schema import CanonicalLog


def _entropy(s: Optional[str]) -> float:
    """Entropie de Shannon d'une chaîne — détecte l'encodage/obfuscation/aléa."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


# Ordre FIXE des features (le modèle attend toujours le même ordre)
FEATURE_NAMES = [
    "clock_skew_seconds",       # écart event/ingest — anormal si manipulé
    "hour_of_day",              # heure — un log à 3h du matin peut dévier
    "event_time_epoch_norm",    # position temporelle normalisée (détecte 1970, futur)
    "cmdline_length",           # longueur de la ligne de commande
    "cmdline_entropy",          # entropie (encodage base64, obfuscation)
    "has_process_context",      # 0/1
    "has_network_target",       # 0/1
    "has_parent_guid",          # 0/1 — un log sans parent peut dévier
    "is_self_parent",           # 0/1 — cohérence de filiation
    "process_name_length",
    "activity_code",            # catégorie d'activité encodée
    "source_ip_present",        # 0/1
]


# Encodage stable des catégories d'activité
_ACTIVITY_CODES = {
    "process": 1, "network_connection": 2, "authentication": 3,
    "file": 4, "registry": 5, "module_load": 6, "process_access": 7,
    "config_change": 8, "resource_management": 9, "other": 0,
}


def extract_features(log: CanonicalLog) -> list[float]:
    """Transforme un log canonique en vecteur de features (ordre = FEATURE_NAMES)."""
    pc = log.process_context

    # temporel
    clock_skew = log.clock_skew_seconds()
    hour = log.event_time.astimezone(timezone.utc).hour
    # position temporelle : nb de jours depuis 2000, normalisé (sensible à 1970/futur)
    epoch_2000 = 946684800.0  # 2000-01-01 en epoch
    days_since_2000 = (log.event_time.timestamp() - epoch_2000) / 86400.0
    # normalisation douce (un 1970 donnera une valeur très négative, un futur très grande)
    epoch_norm = days_since_2000 / 10000.0

    # ligne de commande
    cmdline = pc.command_line if pc else None
    cmd_len = float(len(cmdline)) if cmdline else 0.0
    cmd_ent = _entropy(cmdline)

    # structure / filiation
    has_pc = 1.0 if pc else 0.0
    has_net = 1.0 if (log.target and log.target.destination_ip) else 0.0
    has_parent = 1.0 if (pc and pc.parent_process_guid) else 0.0
    is_self_parent = 1.0 if (pc and pc.process_guid and pc.process_guid == pc.parent_process_guid) else 0.0
    proc_name_len = float(len(pc.process_name)) if (pc and pc.process_name) else 0.0

    activity_code = float(_ACTIVITY_CODES.get(log.activity.value, 0))
    src_ip = 1.0 if (log.actor and log.actor.source_ip) else 0.0

    return [
        clock_skew,
        float(hour),
        epoch_norm,
        cmd_len,
        cmd_ent,
        has_pc,
        has_net,
        has_parent,
        is_self_parent,
        proc_name_len,
        activity_code,
        src_ip,
    ]


def extract_matrix(logs: list[CanonicalLog]) -> list[list[float]]:
    """Extrait la matrice de features pour une liste de logs."""
    return [extract_features(l) for l in logs]
