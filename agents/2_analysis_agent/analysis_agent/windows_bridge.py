"""
=============================================================================
PONT CANONIQUE → ANALYSIS (voie WINDOWS)
=============================================================================
Convertit les `CanonicalLog` produits par le Collect Agent en `Event`
consommables par l'Analysis Agent, puis les regroupe en séquences.

Pendant Windows de `canonical_to_cloud_events` (cloud_adapter). Ce module
manquait : côté Windows, les `Event` n'étaient construits qu'à la main dans
les tests, ce qui empêchait tout fonctionnement de bout en bout.

⚠️ POINT CRITIQUE — L'IDENTIFIANT D'ÉVÉNEMENT
    `CanonicalLog.event_id` est un UUID interne, PAS l'EventID Sysmon.
    Or l'extracteur aligné (`windows_features_aligned`) compte les événements
    par EventID Sysmon (1 = ProcessCreate, 3 = réseau, 8 = injection…).

    Le mapper Sysmon préserve la vraie valeur dans `extra["sysmon_event_id"]`.
    C'est ELLE qui doit alimenter `Event.event_id`, sinon toutes les features
    structurelles vaudraient zéro — silencieusement.

    L'UUID canonique reste disponible dans `extra["canonical_event_id"]` pour
    la traçabilité.

⚠️ SÉQUENÇAGE
    Le modèle Windows a été entraîné avec un séquençage PAR PROCESS_GUID,
    plafonné à 200 événements (cf. `sequencing` dans sa configuration).
    `build_windows_sequences` reproduit exactement ce découpage : toute autre
    stratégie (fenêtre temporelle, par host) décalerait les distributions de
    features par rapport à l'entraînement.
=============================================================================
"""
from __future__ import annotations

from analysis_agent.sequence_schema import Event, Sequence, EventCategory

# Correspondance ActivityCategory (canonique) → EventCategory (Analysis)
_CANONICAL_TO_EVENT_CAT = {
    "process":            EventCategory.PROCESS,
    "network_connection": EventCategory.NETWORK,
    "authentication":     EventCategory.AUTH,
    "file":               EventCategory.FILE,
    "registry":           EventCategory.REGISTRY,
    "module_load":        EventCategory.MODULE_LOAD,
    "process_access":     EventCategory.PROCESS_ACCESS,
    "config_change":      EventCategory.OTHER,
    "resource_management": EventCategory.OTHER,
    "other":              EventCategory.OTHER,
}

# Repli : si l'EventID Sysmon est absent, on le déduit de l'activité.
# Approximation assumée — l'EventID réel reste toujours préférable.
_ACTIVITY_TO_SYSMON_EID = {
    "process":            "1",
    "network_connection": "3",
    "module_load":        "7",
    "process_access":     "8",
    "file":               "11",
    "registry":           "13",
}

WINDOWS_PROVIDERS = ("sysmon", "windows_security", "microsoft-windows")

DEFAULT_SEQUENCE_CAP = 200   # plafond identique à l'entraînement


def _value(x):
    """Valeur d'un enum ou de la chaîne elle-même."""
    return x.value if hasattr(x, "value") else x


def _sysmon_event_id(log) -> str:
    """
    EventID Sysmon réel. Cherche d'abord `extra["sysmon_event_id"]` (posé par
    le mapper), puis se rabat sur une déduction depuis l'activité.
    """
    extra = getattr(log, "extra", None) or {}
    for key in ("sysmon_event_id", "windows_event_id", "event_id"):
        v = extra.get(key)
        if v not in (None, "", "nan"):
            return str(v).strip()
    return _ACTIVITY_TO_SYSMON_EID.get(_value(log.activity), "")


def is_windows_log(log) -> bool:
    """Le log provient-il d'une source Windows (par opposition au cloud) ?"""
    provider = str(getattr(log, "source_provider", "") or "").lower()
    if any(p in provider for p in WINDOWS_PROVIDERS):
        return True
    # à défaut du provider : la présence d'un contexte processus est un indice fiable
    return getattr(log, "process_context", None) is not None


def canonical_to_windows_events(canonical_logs, *, strict: bool = False) -> list[Event]:
    """
    Convertit des CanonicalLog Windows en Event pour l'Analysis Agent.

    strict=True : ignore les logs non-Windows (utile sur un flux mixte).
    """
    events: list[Event] = []
    for log in canonical_logs:
        if strict and not is_windows_log(log):
            continue

        pc = getattr(log, "process_context", None)
        actor = getattr(log, "actor", None)
        target = getattr(log, "target", None)

        category = _CANONICAL_TO_EVENT_CAT.get(_value(log.activity), EventCategory.OTHER)

        # Annotations d'intégrité posées par le Collect (règles R1–R9, autoencoder)
        extra = getattr(log, "extra", None) or {}
        integrity_flags = list(extra.get("integrity_flags") or [])
        if extra.get("integrity_anomaly"):
            integrity_flags.append("integrity_anomaly")

        events.append(Event(
            # ← l'EventID SYSMON, pas l'UUID canonique (voir en-tête)
            event_id=_sysmon_event_id(log),
            event_time=log.event_time,
            category=category,
            host=log.host or "unknown",
            process_guid=pc.process_guid if pc else None,
            parent_process_guid=pc.parent_process_guid if pc else None,
            process_name=pc.process_name if pc else None,
            command_line=pc.command_line if pc else None,
            session_id=getattr(actor, "session_id", None) if actor else None,
            user_name=getattr(actor, "user_name", None) if actor else None,
            source_ip=getattr(actor, "source_ip", None) if actor else None,
            destination_ip=getattr(target, "destination_ip", None) if target else None,
            destination_port=getattr(target, "destination_port", None) if target else None,
            target_name=getattr(target, "name", None) if target else None,
            integrity_flags=integrity_flags,
            extra={
                "canonical_event_id": log.event_id,
                "action_name": log.action_name,
                "outcome": _value(getattr(log, "outcome", None)),
                "source_provider": getattr(log, "source_provider", None),
                "target_type": getattr(target, "type", None) if target else None,
                # champs utiles à l'extracteur aligné.
                # Le mapper Sysmon range TargetProcessGuid dans `target.id`
                # (pour une activité process_access), pas dans `extra`.
                "target_process_guid": (
                    getattr(target, "id", None)
                    if target and getattr(target, "type", None) == "process"
                    else None
                ) or extra.get("target_process_guid") or extra.get("TargetProcessGuid"),
                "hashes": extra.get("hashes") or extra.get("Hashes"),
                "parent_process_name": pc.parent_process_name if pc else None,
                "integrity_level": pc.integrity_level if pc else None,
            },
        ))
    return events


def build_windows_sequences(events, cap: int = DEFAULT_SEQUENCE_CAP) -> list[Sequence]:
    """
    Regroupe les Event en séquences PAR PROCESS_GUID, plafonnées à `cap`
    événements — exactement le découpage utilisé à l'entraînement du modèle.

    Les événements sans process_guid sont regroupés par host (repli), afin de
    ne pas les perdre silencieusement.
    """
    groupes: dict[str, list[Event]] = {}
    for e in events:
        cle = e.process_guid or f"host:{e.host}"
        groupes.setdefault(cle, []).append(e)

    sequences: list[Sequence] = []
    for cle, evts in groupes.items():
        evts.sort(key=lambda x: x.event_time)
        # découpage en tranches de `cap` événements
        for i in range(0, len(evts), cap):
            tranche = evts[i:i + cap]
            suffixe = "" if len(evts) <= cap else f"#{i // cap}"
            sequences.append(Sequence(sequence_id=f"{cle}{suffixe}", events=tranche))
    return sequences


def canonical_to_windows_sequences(canonical_logs, *, cap: int = DEFAULT_SEQUENCE_CAP,
                                   strict: bool = False) -> list[Sequence]:
    """Raccourci : CanonicalLog → séquences prêtes pour le détecteur."""
    return build_windows_sequences(
        canonical_to_windows_events(canonical_logs, strict=strict), cap=cap)
