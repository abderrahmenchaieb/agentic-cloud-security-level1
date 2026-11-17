# =============================================================================
# MAPPER SYSMON → SCHÉMA CANONIQUE
# =============================================================================
# Transforme un événement Sysmon brut (dict) en CanonicalLog.
# Assure aussi la 1re fonction d'intégrité : détecter les MALFORMÉS
# (champs obligatoires manquants, types invalides, EventID inconnu).
#
# Note : Sysmon écrit dans le Windows Event Log. En production, on lit via
# l'API Windows (EvtQuery/pywin32) qui donne un dict par événement. Ici on
# travaille sur ce dict — indépendant de la façon dont il a été récupéré.
# =============================================================================

from __future__ import annotations
from datetime import datetime, timezone
from typing import Optional, Any

from .canonical_schema import (
    CanonicalLog, ValidationResult, SourceType, ActivityCategory, Outcome,
    Actor, Target, ProcessContext,
)


# -----------------------------------------------------------------------------
# Table de correspondance : EventID Sysmon → (activité canonique, nom d'action)
# -----------------------------------------------------------------------------
SYSMON_EVENT_MAP: dict[int, tuple[ActivityCategory, str]] = {
    1:  (ActivityCategory.PROCESS,            "ProcessCreate"),
    3:  (ActivityCategory.NETWORK_CONNECTION, "NetworkConnect"),
    5:  (ActivityCategory.PROCESS,            "ProcessTerminate"),
    7:  (ActivityCategory.MODULE_LOAD,        "ImageLoad"),
    8:  (ActivityCategory.PROCESS_ACCESS,     "CreateRemoteThread"),   # injection
    10: (ActivityCategory.PROCESS_ACCESS,     "ProcessAccess"),        # injection
    11: (ActivityCategory.FILE,               "FileCreate"),
    12: (ActivityCategory.REGISTRY,           "RegistryAdd"),
    13: (ActivityCategory.REGISTRY,           "RegistrySet"),
    22: (ActivityCategory.NETWORK_CONNECTION, "DnsQuery"),
}

# Champs Sysmon strictement obligatoires pour qu'un événement soit exploitable
REQUIRED_FIELDS = ("EventID", "UtcTime", "Computer")


def _parse_sysmon_time(value: Any) -> Optional[datetime]:
    """Sysmon UtcTime : 'YYYY-MM-DD HH:MM:SS.mmm'. Renvoie None si invalide."""
    if not isinstance(value, str):
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _to_int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _build_extra(event_id: int, raw: dict) -> dict:
    """
    Champs conservés dans `extra` : ceux qui n'ont pas de place dans le schéma
    canonique mais que les agents en aval exploitent.

    - `sysmon_event_id` : l'EventID Sysmon réel (1, 3, 8…). Indispensable —
      `CanonicalLog.event_id` est un UUID interne, pas l'EventID.
    - `hashes` : empreintes de l'image (SHA1=…,MD5=…,IMPHASH=…), présentes sur
      les EID 1 (ProcessCreate), 6 (DriverLoad) et 7 (ImageLoad). Alimente la
      feature `n_hash` du détecteur Windows.
    """
    extra: dict[str, Any] = {"sysmon_event_id": event_id}
    hashes = raw.get("Hashes")
    if hashes not in (None, "", "nan"):
        extra["hashes"] = str(hashes)
    return extra


def map_sysmon_event(raw: dict, replay_mode: bool = False) -> ValidationResult:
    """
    Transforme un événement Sysmon brut en CanonicalLog.
    Renvoie un ValidationResult : soit un log valide, soit un rejet motivé
    (= détection de malformé).

    replay_mode : pour les données HISTORIQUES rejouées (datasets type COMISET).
        En temps réel, `ingest_time` vaut l'instant de l'ingestion — l'écart
        avec `event_time` mesure alors une vraie dérive d'horloge (règle R3).
        Sur un dataset rejoué des années plus tard, cet écart atteint des
        centaines de jours et R3_clock_skew se déclenche sur CHAQUE événement.
        En mode replay, `ingest_time` est donc aligné sur `event_time`.
        Symétrique de `AwsCloudTrailAdapter(replay_mode=...)` côté cloud.
    """
    # --- 1. VALIDATION D'INTÉGRITÉ : champs obligatoires présents ? ---
    if not isinstance(raw, dict):
        return ValidationResult(is_valid=False, rejection_reason="not_a_dict", raw=None)

    for field in REQUIRED_FIELDS:
        if field not in raw or raw[field] in (None, ""):
            return ValidationResult(
                is_valid=False,
                rejection_reason=f"missing_required_field:{field}",
                raw=raw,
            )

    # --- 2. EventID connu ? ---
    event_id = _to_int(raw.get("EventID"))
    if event_id is None:
        return ValidationResult(is_valid=False, rejection_reason="invalid_event_id", raw=raw)
    if event_id not in SYSMON_EVENT_MAP:
        return ValidationResult(
            is_valid=False,
            rejection_reason=f"unsupported_event_id:{event_id}",
            raw=raw,
        )

    # --- 3. Temps valide ? ---
    event_time = _parse_sysmon_time(raw.get("UtcTime"))
    if event_time is None:
        return ValidationResult(is_valid=False, rejection_reason="invalid_utctime", raw=raw)

    activity, action_name = SYSMON_EVENT_MAP[event_id]

    # --- 4. Construction des blocs communs ---
    actor = Actor(
        user_name=raw.get("User"),
        session_id=raw.get("LogonId"),
        source_ip=raw.get("SourceIp"),  # présent pour EID 3 (réseau)
    )

    # process_context : présent pour tous les événements endpoint Sysmon
    process_context = ProcessContext(
        process_guid=raw.get("ProcessGuid"),
        process_id=_to_int(raw.get("ProcessId")),
        process_name=raw.get("Image"),
        command_line=raw.get("CommandLine"),
        parent_process_guid=raw.get("ParentProcessGuid"),
        parent_process_id=_to_int(raw.get("ParentProcessId")),
        parent_process_name=raw.get("ParentImage"),
        integrity_level=raw.get("IntegrityLevel"),
    )

    # target : dépend du type d'événement
    target = Target()
    if activity == ActivityCategory.NETWORK_CONNECTION:
        target = Target(
            type="network_endpoint",
            destination_ip=raw.get("DestinationIp"),
            destination_port=_to_int(raw.get("DestinationPort")),
            protocol=raw.get("Protocol"),
        )
    elif activity == ActivityCategory.FILE:
        target = Target(type="file", name=raw.get("TargetFilename"))
    elif activity == ActivityCategory.REGISTRY:
        target = Target(type="registry_key", name=raw.get("TargetObject"))
    elif activity == ActivityCategory.PROCESS_ACCESS:
        # injection : la cible est un AUTRE processus
        target = Target(
            type="process",
            name=raw.get("TargetImage"),
            id=raw.get("TargetProcessGuid"),
        )

    # --- 5. Assemblage du log canonique ---
    try:
        log = CanonicalLog(
            source_type=SourceType.ENDPOINT,
            source_provider="sysmon",
            event_time=event_time,
            activity=activity,
            action_name=action_name,
            outcome=Outcome.SUCCESS,  # Sysmon journalise surtout des faits accomplis
            host=raw.get("Computer"),
            actor=actor,
            target=target,
            process_context=process_context,
            raw_ref=raw.get("RecordNumber"),
            # `Hashes` : empreintes de l'image (SHA1=…,MD5=…,IMPHASH=…), présent
            # sur les EID 1/6/7. Utilisé par la feature `n_hash` du détecteur
            # Windows (nombre d'empreintes distinctes dans une séquence).
            extra=_build_extra(event_id, raw),
            # en rejeu de données historiques, l'ingestion est datée de
            # l'événement lui-même (voir docstring : évite R3_clock_skew massif)
            **({"ingest_time": event_time} if replay_mode else {}),
        )
    except Exception as e:
        # Un champ a un type inattendu qui casse la validation Pydantic → malformé
        return ValidationResult(is_valid=False, rejection_reason=f"schema_error:{e}", raw=raw)

    return ValidationResult(is_valid=True, log=log)
