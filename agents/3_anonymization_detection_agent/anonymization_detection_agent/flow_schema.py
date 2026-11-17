# =============================================================================
# CONTRAT D'ENTRÉE — Anonymization Detection Agent
# =============================================================================
# Structure d'un FLUX réseau. C'est le point de compatibilité critique :
# elle doit correspondre à la fois à
#   - ce que la SONDE produit (tshark + CICFlowMeter), et
#   - ce que CIC-Darknet2020 contient (features CICFlowMeter + IP).
#
# Deux niveaux d'information dans un flux :
#   1. IDENTITÉ (5-tuple + IP) → suffit pour l'ÉTAPE 1 (lookup)
#   2. FEATURES statistiques    → nécessaires pour l'ÉTAPE 2 (GNN)
#
# On sépare clairement les deux, car l'étape 1 n'a pas besoin des features.
# =============================================================================

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class AnonymizationLabel(str, Enum):
    """Étiquette de sortie (et label du dataset)."""
    NORMAL = "normal"          # trafic non anonymisé
    VPN = "vpn"
    TOR = "tor"
    UNKNOWN = "unknown"        # non encore déterminé


@dataclass
class FlowFeatures:
    """
    Features statistiques d'un flux (style CICFlowMeter).
    Ce sont ces valeurs que le GNN utilise (étape 2).

    On ne liste PAS les ~80 features une par une ici : on garde un dict
    'values' (nom → valeur) pour rester flexible face aux variations de
    version de CICFlowMeter. Les features CANONIQUES (toujours attendues)
    sont exposées en attributs pour un accès direct.

    Principe validé : la sonde doit produire le MÊME TYPE de features que
    CIC-Darknet2020 (pas identiques au bit près). On vérifie que les colonnes
    correspondent via feature_names.
    """
    # features canoniques (présentes dans CIC-Darknet2020 ET calculables par la sonde)
    flow_duration: float = 0.0
    total_fwd_packets: float = 0.0
    total_bwd_packets: float = 0.0
    total_length_fwd: float = 0.0
    total_length_bwd: float = 0.0
    flow_bytes_per_s: float = 0.0
    flow_packets_per_s: float = 0.0
    flow_iat_mean: float = 0.0
    flow_iat_std: float = 0.0
    fwd_packet_length_mean: float = 0.0
    bwd_packet_length_mean: float = 0.0
    down_up_ratio: float = 0.0

    # toutes les autres features CICFlowMeter (dict extensible)
    extra: dict[str, float] = field(default_factory=dict)

    def to_vector(self, feature_order: list[str]) -> list[float]:
        """Produit un vecteur dans un ordre de features donné (pour le GNN)."""
        canonical = {
            "flow_duration": self.flow_duration,
            "total_fwd_packets": self.total_fwd_packets,
            "total_bwd_packets": self.total_bwd_packets,
            "total_length_fwd": self.total_length_fwd,
            "total_length_bwd": self.total_length_bwd,
            "flow_bytes_per_s": self.flow_bytes_per_s,
            "flow_packets_per_s": self.flow_packets_per_s,
            "flow_iat_mean": self.flow_iat_mean,
            "flow_iat_std": self.flow_iat_std,
            "fwd_packet_length_mean": self.fwd_packet_length_mean,
            "bwd_packet_length_mean": self.bwd_packet_length_mean,
            "down_up_ratio": self.down_up_ratio,
        }
        vec = []
        for name in feature_order:
            if name in canonical:
                vec.append(float(canonical[name]))
            else:
                vec.append(float(self.extra.get(name, 0.0)))
        return vec


@dataclass
class NetworkFlow:
    """
    Un flux réseau complet.
    IDENTITÉ (5-tuple + IP) + FEATURES statistiques.
    """
    # --- Identité (étape 1 : lookup) ---
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    timestamp: Optional[str] = None

    # --- Features (étape 2 : GNN) ---
    features: FlowFeatures = field(default_factory=FlowFeatures)

    # --- Label (connu à l'entraînement, None en production) ---
    label: AnonymizationLabel = AnonymizationLabel.UNKNOWN

    def external_ip(self, internal_prefixes: tuple[str, ...] = ("10.", "192.168.", "172."),
                    known_external: Optional[set] = None) -> Optional[str]:
        """
        Identifie l'IP EXTERNE du flux (celle à interroger au lookup).
        Heuristique : l'IP qui n'est pas dans une plage privée.

        ⚠️ CAS DES DEUX IP PUBLIQUES
            Sur la voie cloud, l'attaquant appelle DEPUIS l'extérieur vers un
            endpoint AWS : les deux extrémités sont publiques. Retourner `dst`
            par défaut désignerait alors l'endpoint AWS — pas l'attaquant —
            et l'anonymisation serait attribuée à la mauvaise adresse : le
            Decision Agent ne pourrait plus corréler menace et anonymisation.

            `known_external` permet de lever l'ambiguïté en indiquant les IP
            déjà identifiées comme suspectes (nœuds Tor, plages VPN) : si
            l'une des deux extrémités en fait partie, c'est celle-là.
        """
        src_internal = any(self.src_ip.startswith(p) for p in internal_prefixes)
        dst_internal = any(self.dst_ip.startswith(p) for p in internal_prefixes)
        if src_internal and not dst_internal:
            return self.dst_ip
        if dst_internal and not src_internal:
            return self.src_ip
        # les deux externes : privilégier celle qui est déjà connue comme suspecte
        if known_external:
            if self.src_ip in known_external:
                return self.src_ip
            if self.dst_ip in known_external:
                return self.dst_ip
        # les deux internes, ou aucune information : dst par défaut
        return self.dst_ip


@dataclass
class AnonymizationVerdict:
    """Sortie de l'agent pour un flux."""
    flow_id: str
    external_ip: Optional[str]
    label: AnonymizationLabel
    confidence: float
    method: str                 # "lookup" | "gnn_supervised" | "gnn_anomaly"
    detail: str = ""
