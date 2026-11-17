# =============================================================================
# CONSTRUCTION DU GRAPHE DE FLUX
# =============================================================================
# Transforme une liste de NetworkFlow en graphe pour le GNN.
#
# Modèle E-GraphSAGE :
#   - NŒUDS   = adresses IP (hôtes)
#   - ARÊTES  = flux entre IP
#   - FEATURES portées par les ARÊTES (les flux), pas les nœuds
#   - les nœuds reçoivent un vecteur constant (E-GraphSAGE : vecteur de 1)
#   - la CLASSIFICATION se fait sur les ARÊTES (chaque flux = normal/vpn/tor)
#
# On produit une structure indépendante du framework (indices + tenseurs),
# convertible ensuite en graphe DGL/PyG pour l'entraînement.
# =============================================================================

from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
import numpy as np

from .flow_schema import NetworkFlow, AnonymizationLabel


# ordre canonique des features d'arête (doit être stable train/production)
DEFAULT_EDGE_FEATURES = [
    "flow_duration", "total_fwd_packets", "total_bwd_packets",
    "total_length_fwd", "total_length_bwd", "flow_bytes_per_s",
    "flow_packets_per_s", "flow_iat_mean", "flow_iat_std",
    "fwd_packet_length_mean", "bwd_packet_length_mean", "down_up_ratio",
]

_LABEL_TO_INT = {
    AnonymizationLabel.NORMAL: 0,
    AnonymizationLabel.VPN: 1,
    AnonymizationLabel.TOR: 2,
    AnonymizationLabel.UNKNOWN: -1,
}


@dataclass
class FlowGraph:
    """
    Graphe de flux prêt pour le GNN.
      node_ids       : liste des IP (index = id de nœud)
      edge_src       : indices des nœuds source (par arête)
      edge_dst       : indices des nœuds destination
      edge_features  : matrice [n_edges, n_features]
      edge_labels    : [n_edges] (0=normal,1=vpn,2=tor,-1=inconnu)
      feature_names  : ordre des features
    """
    node_ids: list[str]
    edge_src: np.ndarray
    edge_dst: np.ndarray
    edge_features: np.ndarray
    edge_labels: np.ndarray
    feature_names: list[str]

    @property
    def n_nodes(self) -> int:
        return len(self.node_ids)

    @property
    def n_edges(self) -> int:
        return len(self.edge_src)

    def summary(self) -> dict:
        uniq, counts = np.unique(self.edge_labels, return_counts=True)
        label_dist = {int(u): int(c) for u, c in zip(uniq, counts)}
        return {
            "n_nodes": self.n_nodes,
            "n_edges": self.n_edges,
            "n_features": self.edge_features.shape[1],
            "edge_label_dist": label_dist,
        }


class GraphBuilder:
    """Construit un FlowGraph à partir de flux."""

    def __init__(self, edge_features: Optional[list[str]] = None):
        self.feature_names = edge_features or DEFAULT_EDGE_FEATURES

    def build(self, flows: list[NetworkFlow], normalize: bool = True) -> FlowGraph:
        # 1. indexer les IP → nœuds
        ip_to_idx: dict[str, int] = {}
        def node_index(ip: str) -> int:
            if ip not in ip_to_idx:
                ip_to_idx[ip] = len(ip_to_idx)
            return ip_to_idx[ip]

        edge_src, edge_dst, feats, labels = [], [], [], []
        for f in flows:
            s = node_index(f.src_ip)
            d = node_index(f.dst_ip)
            edge_src.append(s)
            edge_dst.append(d)
            feats.append(f.features.to_vector(self.feature_names))
            labels.append(_LABEL_TO_INT.get(f.label, -1))

        node_ids = [ip for ip, _ in sorted(ip_to_idx.items(), key=lambda kv: kv[1])]
        edge_features = np.array(feats, dtype=np.float32)
        edge_labels = np.array(labels, dtype=np.int64)

        # 2. normaliser les features d'arête (log1p pour les grandes échelles + z-score)
        if normalize and len(edge_features) > 0:
            edge_features = self._normalize(edge_features)

        return FlowGraph(
            node_ids=node_ids,
            edge_src=np.array(edge_src, dtype=np.int64),
            edge_dst=np.array(edge_dst, dtype=np.int64),
            edge_features=edge_features,
            edge_labels=edge_labels,
            feature_names=self.feature_names,
        )

    def _normalize(self, X: np.ndarray) -> np.ndarray:
        # log1p sur les valeurs positives à grande dynamique, puis standardisation
        X = np.sign(X) * np.log1p(np.abs(X))
        mean = X.mean(axis=0)
        std = X.std(axis=0) + 1e-9
        return ((X - mean) / std).astype(np.float32)
