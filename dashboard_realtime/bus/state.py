# =============================================================================
# MODÈLE D'ÉTAT DU BUS RÉSEAU
# =============================================================================
# Le bus réseau maintient l'état GLOBAL du système, alimenté par les événements
# que les agents publient. C'est la source de vérité du dashboard.
#
# Quatre familles d'état, correspondant aux 4 zones du dashboard :
#   - hosts       (zone 2) : les hôtes surveillés et leur situation
#   - positions   (zone 1) : les positions géo (IP correcte / anonymisée)
#   - cooperation (zone 3) : le journal des échanges inter-agents
#   - attacks     (zone 4) : les attaques en cours (timeline MITRE + décision)
# =============================================================================

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# -----------------------------------------------------------------------------
# ZONE 2 — état d'un hôte
# -----------------------------------------------------------------------------
class ConnectionState(str, Enum):
    CONNECTED = "connected"          # envoie des logs normalement
    SILENT_NORMAL = "silent_normal"  # silencieux (probablement éteint)
    SILENT_ANOMALOUS = "silent_anomalous"  # silence ANORMAL → suppression suspectée


class SecurityState(str, Enum):
    NORMAL = "normal"
    MONITORED = "monitored"          # signal faible (falsif seule)
    UNDER_INVESTIGATION = "under_investigation"
    UNDER_ATTACK = "under_attack"    # attaque confirmée


@dataclass
class HostState:
    host_id: str
    connection: ConnectionState = ConnectionState.CONNECTED
    security: SecurityState = SecurityState.NORMAL
    integrity_ok: bool = True         # logs fiables (pas de falsification)
    source_type: str = "endpoint"     # endpoint | cloud
    last_seen: str = field(default_factory=_now)
    event_count: int = 0
    detail: str = ""

    def to_dict(self):
        d = asdict(self)
        d["connection"] = self.connection.value
        d["security"] = self.security.value
        return d


# -----------------------------------------------------------------------------
# ZONE 1 — une position géographique
# -----------------------------------------------------------------------------
class IpKind(str, Enum):
    CLEAR = "clear"              # IP normale → géoloc utile
    ANONYMIZED_TOR = "tor"      # nœud de sortie Tor → PAS l'attaquant
    ANONYMIZED_VPN = "vpn"      # serveur VPN → PAS l'attaquant


@dataclass
class GeoPosition:
    ip: str
    ip_kind: IpKind = IpKind.CLEAR
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    country: Optional[str] = None
    city: Optional[str] = None
    is_attacker: bool = False
    host_id: Optional[str] = None       # l'hôte associé
    # HONNÊTETÉ : pour une IP anonymisée, la position est celle du nœud de
    # sortie, PAS de l'attaquant. Le Niveau 2 devrait percer l'origine réelle.
    position_is_real: bool = True       # False si anonymisé (position = relais)
    detail: str = ""

    def to_dict(self):
        d = asdict(self)
        d["ip_kind"] = self.ip_kind.value
        return d


# -----------------------------------------------------------------------------
# ZONE 3 — un échange inter-agents
# -----------------------------------------------------------------------------
@dataclass
class CooperationEvent:
    timestamp: str
    sender: str
    responder: str
    request_type: str
    detail: str
    success: bool = True

    def to_dict(self):
        return asdict(self)


# -----------------------------------------------------------------------------
# ZONE 4 — une attaque en cours
# -----------------------------------------------------------------------------
@dataclass
class AttackTimelineStep:
    timestamp: str
    tactic: str            # tactique MITRE (Initial Access, Execution...)
    technique_id: str
    technique_name: str
    detail: str = ""

    def to_dict(self):
        return asdict(self)


@dataclass
class AttackCase:
    entity_key: str
    host_id: str
    threat_score: float = 0.0
    certainty: str = "normal"           # confirmed / doubtful / normal / monitored
    escalate: bool = False
    mission: str = "none"               # geolocation / investigation
    triggered_rules: list = field(default_factory=list)
    timeline: list = field(default_factory=list)      # list[AttackTimelineStep]
    recommended_actions: list = field(default_factory=list)  # actions + priorité
    anonymized_ips: list = field(default_factory=list)       # IP à percer (N2)
    started_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)

    def to_dict(self):
        d = asdict(self)
        d["timeline"] = [s if isinstance(s, dict) else s.to_dict() for s in self.timeline]
        return d


# -----------------------------------------------------------------------------
# ÉTAT GLOBAL — ce que le bus maintient et diffuse
# -----------------------------------------------------------------------------
class SystemState:
    def __init__(self):
        self.hosts: dict[str, HostState] = {}
        self.positions: dict[str, GeoPosition] = {}   # par IP
        # ⚠️ File BORNÉE : l'état n'expose que les 50 derniers échanges, mais
        #    une liste ordinaire continuerait de croître indéfiniment en
        #    mémoire — sur un flux continu, c'est une fuite. `deque(maxlen=)`
        #    écarte automatiquement les plus anciens.
        from collections import deque
        self.cooperation: deque = deque(maxlen=500)
        self.attacks: dict[str, AttackCase] = {}      # par entity_key
        self.stats = {"events_endpoint": 0, "events_cloud": 0,
                      "sequences": 0, "llm_calls": 0, "escalations": 0}

    def snapshot(self) -> dict:
        """L'état complet, sérialisable (pour le dashboard à la connexion)."""
        return {
            "hosts": [h.to_dict() for h in self.hosts.values()],
            "positions": [p.to_dict() for p in self.positions.values()],
            # un deque ne supporte pas le découpage : on matérialise la liste
            "cooperation": [c.to_dict() for c in list(self.cooperation)[-50:]],
            "attacks": [a.to_dict() for a in self.attacks.values()],
            "stats": self.stats,
            "generated_at": _now(),
        }
