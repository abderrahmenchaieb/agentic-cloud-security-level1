from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Any


def _est_privee(ip: str) -> bool:
    """
    Adresse d'un réseau privé, de bouclage ou lien-local.

    Les IP internes ne sont pas des « IP externes » : les remonter
    polluerait la corrélation (toutes les machines d'un même réseau
    partageraient des IP communes sans rapport avec une attaque).
    """
    try:
        import ipaddress
        a = ipaddress.ip_address(str(ip).strip())
        return a.is_private or a.is_loopback or a.is_link_local or a.is_reserved
    except Exception:
        return False


class EventCategory(str, Enum):
    PROCESS = "process"
    NETWORK = "network_connection"
    FILE = "file"
    REGISTRY = "registry"
    AUTH = "authentication"
    MODULE_LOAD = "module_load"
    PROCESS_ACCESS = "process_access"
    OTHER = "other"


@dataclass
class Event:
    event_id: str
    event_time: datetime
    category: EventCategory
    host: str
    process_guid: Optional[str] = None
    parent_process_guid: Optional[str] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    session_id: Optional[str] = None
    user_name: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    target_name: Optional[str] = None
    integrity_flags: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class Sequence:
    sequence_id: str
    events: list[Event] = field(default_factory=list)
    host: Optional[str] = None
    root_process_guid: Optional[str] = None

    @property
    def start_time(self) -> Optional[datetime]:
        return min((e.event_time for e in self.events), default=None)

    @property
    def end_time(self) -> Optional[datetime]:
        return max((e.event_time for e in self.events), default=None)

    @property
    def duration_seconds(self) -> float:
        if not self.events or self.start_time == self.end_time:
            return 0.0
        return (self.end_time - self.start_time).total_seconds()

    @property
    def n_events(self) -> int:
        return len(self.events)

    def process_names(self) -> list[str]:
        seen = []
        for e in self.events:
            if e.process_name and e.process_name not in seen:
                seen.append(e.process_name)
        return seen

    def has_network(self) -> bool:
        return any(e.category == EventCategory.NETWORK for e in self.events)

    def external_ips(self) -> list[str]:
        """
        IP externes vues dans la séquence.

        ⚠️ LES DEUX VOIES N'ONT PAS LA MÊME NOTION D'« IP EXTERNE »
            Windows : la machine surveillée se connecte VERS l'extérieur —
                      l'IP externe est `destination_ip`.
            Cloud   : l'appelant vient DE l'extérieur vers l'API AWS —
                      l'IP externe est `source_ip` (sourceIPAddress).

            Ne lire que `destination_ip` laissait les séquences cloud sans
            aucune IP : le Decision Agent, qui corrèle menace et anonymisation
            par intersection d'IP, ne pouvait jamais rapprocher les deux
            signaux d'un incident cloud.
        """
        ips = []
        for e in self.events:
            for ip in (e.destination_ip, e.source_ip):
                if ip and not _est_privee(ip) and ip not in ips:
                    ips.append(ip)
        return ips

    def integrity_flags(self) -> list[str]:
        flags = []
        for e in self.events:
            flags.extend(e.integrity_flags)
        return flags

    def observed_artifacts(self) -> list[str]:
        """
        Artefacts numériques RÉELLEMENT observés dans la séquence, dérivés des
        catégories d'événements. Consommé par le Decision Agent pour le
        raffinement D3FEND "niveau artefacts" (proposer les défenses qui
        opèrent sur ce qui s'est vraiment passé, pas sur la technique abstraite).

        Renvoie des étiquettes d'artefact NEUTRES (pas encore des IDs D3FEND) :
        le mapping vers l'ontologie D3FEND (d3f:NetworkTraffic, d3f:File, ...)
        vit dans le Decision Agent, qui porte la connaissance défensive.
        """
        mapping = {
            EventCategory.NETWORK: "network_traffic",
            EventCategory.FILE: "file",
            EventCategory.REGISTRY: "registry_key",
            EventCategory.PROCESS: "process",
            EventCategory.PROCESS_ACCESS: "process_access",
            EventCategory.MODULE_LOAD: "module_load",
            EventCategory.AUTH: "authentication",
        }
        seen = []
        for e in self.events:
            art = mapping.get(e.category)
            if art and art not in seen:
                seen.append(art)
        return seen

    def summary(self) -> dict:
        return {
            "sequence_id": self.sequence_id,
            "host": self.host,
            "n_events": self.n_events,
            "duration_s": round(self.duration_seconds, 1),
            "processes": self.process_names(),
            "has_network": self.has_network(),
            "external_ips": self.external_ips(),
            "observed_artifacts": self.observed_artifacts(),
        }
