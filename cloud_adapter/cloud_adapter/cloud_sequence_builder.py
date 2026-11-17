# =============================================================================
# SEQUENCE BUILDER CLOUD — corrélation des événements cloud en séquences
# =============================================================================
# L'Analysis Agent corrèle les séquences Windows par ProcessGUID (filiation de
# processus). Le cloud n'a PAS de ProcessGUID. Ce module fournit l'équivalent :
#
#   1. canonical_to_cloud_events() : CanonicalLog (cloud) → Event de l'Analysis
#      (mappe acteur/session/IP/cible ; pas de process_guid, mais session_id rempli)
#
#   2. CloudSequenceBuilder : regroupe les Event cloud en Sequence par
#      ACTEUR + SESSION (la clé de corrélation cloud), avec fenêtre temporelle.
#      → une séquence = les actions d'un même principal dans une même session.
#
# Produit les MÊMES Sequence que le builder Windows : l'Analysis Agent (détecteur
# ML + LLM) fonctionne ensuite SANS modification. Seule la construction change.
# =============================================================================

from __future__ import annotations
from dataclasses import dataclass
from datetime import timedelta
from typing import Optional
import uuid

try:
    from sequence_schema import Event, Sequence, EventCategory
except ImportError:
    from analysis_agent.sequence_schema import Event, Sequence, EventCategory


# mapping ActivityCategory (canonique) → EventCategory (Analysis)
# le pont sémantique côté Analysis
_CANONICAL_TO_EVENT_CAT = {
    "process": EventCategory.PROCESS,
    "network_connection": EventCategory.NETWORK,
    "authentication": EventCategory.AUTH,
    "file": EventCategory.FILE,
    "registry": EventCategory.REGISTRY,
    "module_load": EventCategory.MODULE_LOAD,
    "process_access": EventCategory.PROCESS_ACCESS,
    # spécifiques cloud → catégories les plus proches
    "config_change": EventCategory.REGISTRY,        # changement de config ≈ modif d'état persistant
    "resource_management": EventCategory.PROCESS,    # création de calcul ≈ "process"
    "other": EventCategory.OTHER,
}


def canonical_to_cloud_events(canonical_logs) -> list[Event]:
    """Convertit des CanonicalLog cloud en Event pour l'Analysis Agent."""
    events = []
    for log in canonical_logs:
        actor = log.actor
        cc = log.cloud_context
        cat = _CANONICAL_TO_EVENT_CAT.get(
            log.activity.value if hasattr(log.activity, "value") else log.activity,
            EventCategory.OTHER)

        events.append(Event(
            event_id=log.event_id,
            event_time=log.event_time,
            category=cat,
            # "host" logique côté cloud = le principal (acteur)
            host=(actor.user_id if actor else None) or (log.host or "cloud"),
            # pas de process_guid dans le cloud → None (le builder cloud n'en a pas besoin)
            process_guid=None,
            parent_process_guid=None,
            # l'action API joue le rôle du "process_name" (ce qui a été fait)
            process_name=(cc.api_call if cc else None) or log.action_name,
            command_line=None,
            # LA CLÉ DE CORRÉLATION CLOUD :
            session_id=actor.session_id if actor else None,
            user_name=actor.user_name if actor else None,
            source_ip=actor.source_ip if actor else None,
            target_name=log.target.name if log.target else None,
            integrity_flags=[],
            extra={
                "cloud_service": cc.service if cc else None,
                "cloud_provider": cc.provider if cc else None,
                "principal_type": actor.principal_type if actor else None,
                "outcome": log.outcome.value if hasattr(log.outcome, "value") else str(log.outcome),
                "account_id": actor.account_id if actor else None,
            },
        ))
    return events


@dataclass
class CloudSequenceBuilderConfig:
    time_window_seconds: float = 900.0   # 15 min (les attaques cloud sont plus étalées)
    # clé de corrélation : "session" (défaut) ou "principal" (par acteur, sessions fusionnées)
    correlation_key: str = "session"


class CloudSequenceBuilder:
    """
    Regroupe les Event cloud en Sequence par acteur/session.
    Équivalent cloud du SequenceBuilder Windows (qui, lui, regroupe par ProcessGUID).
    """

    def __init__(self, config: Optional[CloudSequenceBuilderConfig] = None):
        self.config = config or CloudSequenceBuilderConfig()

    def build(self, events: list[Event]) -> list[Sequence]:
        events = sorted(events, key=lambda e: e.event_time)
        groups: dict[str, list[Event]] = {}

        for e in events:
            key = self._correlation_key(e)
            groups.setdefault(key, []).append(e)

        # découper chaque groupe par fenêtre temporelle (sessions longues)
        sequences: list[Sequence] = []
        for key, evs in groups.items():
            sequences.extend(self._split_by_time_window(evs))
        return sequences

    def _correlation_key(self, e: Event) -> str:
        """La clé qui regroupe : acteur + session (ou acteur seul si 'principal')."""
        principal = e.host or "unknown"          # host = arn du principal (posé par le convertisseur)
        if self.config.correlation_key == "principal":
            return f"p:{principal}"
        # défaut : acteur + session
        session = e.session_id or "no-session"
        return f"s:{principal}:{session}"

    def _split_by_time_window(self, events: list[Event]) -> list[Sequence]:
        events = sorted(events, key=lambda e: e.event_time)
        window = self.config.time_window_seconds
        sequences: list[Sequence] = []
        current: list[Event] = []
        for e in events:
            if not current:
                current = [e]
                continue
            gap = (e.event_time - current[-1].event_time).total_seconds()
            if gap > window:
                sequences.append(self._make_sequence(current))
                current = [e]
            else:
                current.append(e)
        if current:
            sequences.append(self._make_sequence(current))
        return sequences

    def _make_sequence(self, events: list[Event]) -> Sequence:
        events = sorted(events, key=lambda e: e.event_time)
        return Sequence(
            sequence_id=f"cloudseq-{uuid.uuid4().hex[:8]}",
            events=events,
            host=events[0].host,             # le principal
            root_process_guid=None,          # pas de notion de racine processus dans le cloud
        )
