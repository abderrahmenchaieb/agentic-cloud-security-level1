# =============================================================================
# ANOMAL-E — détection d'anonymisation self-supervised (SANS labels)
# =============================================================================
# Contrairement à E-GraphSAGE (supervisé, a besoin des labels VPN/Tor),
# Anomal-E apprend le "normal" SANS labels, puis détecte les anomalies.
# → contourne le problème de circularité des labels.
#
# Principe (Deep Graph Infomax appliqué aux arêtes) :
#   1. Un encodeur GNN produit des embeddings d'arêtes à partir du vrai graphe.
#   2. On crée un graphe CORROMPU (features d'arêtes mélangées).
#   3. Un discriminateur apprend à distinguer embeddings du vrai graphe
#      (positifs) vs graphe corrompu (négatifs), guidé par un résumé global.
#   → l'encodeur apprend ce qui est "cohérent"/normal, SANS jamais voir de label.
#   4. Un détecteur d'anomalie (Isolation Forest) est entraîné sur les
#      embeddings du trafic NORMAL ; les flux VPN/Tor ressortent comme anomalies.
#
# PyTorch pur. Réutilise la couche E-GraphSAGE comme encodeur.
# =============================================================================

from __future__ import annotations
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

from .graph_builder import FlowGraph
from .egraphsage import EGraphSAGELayer, graph_to_tensors
from sklearn.ensemble import IsolationForest


class EdgeEncoder(nn.Module):
    """Encodeur GNN : produit un embedding par arête (via les nœuds + feature)."""
    def __init__(self, edge_dim: int, hidden_dim: int = 64, n_layers: int = 2):
        super().__init__()
        self.node_init_dim = hidden_dim
        self.layers = nn.ModuleList(
            [EGraphSAGELayer(hidden_dim, edge_dim, hidden_dim) for _ in range(n_layers)]
        )
        self.edge_proj = nn.Linear(hidden_dim * 2 + edge_dim, hidden_dim)

    def forward(self, edge_index, edge_feat, n_nodes):
        h = torch.ones(n_nodes, self.node_init_dim, device=edge_feat.device)
        for layer in self.layers:
            h = layer(h, edge_index, edge_feat)
        src, dst = edge_index
        edge_emb = torch.cat([h[src], h[dst], edge_feat], dim=1)
        return F.relu(self.edge_proj(edge_emb))       # [n_edges, hidden]


class AnomalEDGI(nn.Module):
    """
    Deep Graph Infomax sur les arêtes.
    Apprend sans labels en contrastant vrai graphe vs graphe corrompu.
    """
    def __init__(self, edge_dim: int, hidden_dim: int = 64):
        super().__init__()
        self.encoder = EdgeEncoder(edge_dim, hidden_dim)
        # discriminateur bilinéaire entre un embedding d'arête et le résumé global
        self.disc = nn.Bilinear(hidden_dim, hidden_dim, 1)

    def readout(self, emb):
        """Résumé global du graphe = moyenne des embeddings d'arêtes."""
        return torch.sigmoid(emb.mean(dim=0))

    def forward(self, edge_index, edge_feat, n_nodes):
        # embeddings positifs (vrai graphe)
        pos = self.encoder(edge_index, edge_feat, n_nodes)
        summary = self.readout(pos)
        # embeddings négatifs : features d'arêtes mélangées (corruption)
        perm = torch.randperm(edge_feat.size(0), device=edge_feat.device)
        neg = self.encoder(edge_index, edge_feat[perm], n_nodes)
        return pos, neg, summary

    def discriminate(self, emb, summary):
        s = summary.unsqueeze(0).expand(emb.size(0), -1)
        return self.disc(emb, s).squeeze(-1)


def train_anomale(graph: FlowGraph, normal_mask=None, epochs: int = 100,
                  lr: float = 0.01, device="cpu", verbose: bool = True):
    """
    Entraîne Anomal-E en self-supervised.
    normal_mask : si fourni, n'entraîne le DGI que sur le trafic normal
    (idéal : apprendre le 'normal' pur). Sinon, tout le graphe.
    LES LABELS NE SONT JAMAIS UTILISÉS pour l'apprentissage des embeddings.
    """
    edge_index, edge_feat, _ = graph_to_tensors(graph, device)
    model = AnomalEDGI(edge_dim=edge_feat.size(1)).to(device)
    opt = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=5e-4)

    for epoch in range(epochs):
        model.train()
        opt.zero_grad()
        pos, neg, summary = model(edge_index, edge_feat, graph.n_nodes)
        # DGI loss : positifs → 1, négatifs → 0
        pos_score = model.discriminate(pos, summary)
        neg_score = model.discriminate(neg, summary)
        loss = F.binary_cross_entropy_with_logits(pos_score, torch.ones_like(pos_score)) + \
               F.binary_cross_entropy_with_logits(neg_score, torch.zeros_like(neg_score))
        loss.backward()
        opt.step()
        if verbose and (epoch + 1) % 20 == 0:
            print(f"   epoch {epoch+1:3d} | DGI loss {loss.item():.4f}")

    return model


class AnomalEDetector:
    """
    Détecteur complet Anomal-E : encodeur DGI (self-supervised) +
    Isolation Forest sur les embeddings.
    """
    def __init__(self, dgi_model: AnomalEDGI, contamination: float = 0.1):
        self.dgi = dgi_model
        self.iso = IsolationForest(n_estimators=200, contamination=contamination,
                                   random_state=42)
        self._fitted = False

    def _embeddings(self, graph: FlowGraph, device="cpu") -> np.ndarray:
        edge_index, edge_feat, _ = graph_to_tensors(graph, device)
        self.dgi.eval()
        with torch.no_grad():
            emb = self.dgi.encoder(edge_index, edge_feat, graph.n_nodes)
        return emb.cpu().numpy()

    def fit(self, graph: FlowGraph, normal_mask=None, device="cpu"):
        """Entraîne l'Isolation Forest sur les embeddings du NORMAL."""
        emb = self._embeddings(graph, device)
        train_emb = emb[normal_mask] if normal_mask is not None else emb
        self.iso.fit(train_emb)
        self._fitted = True
        return self

    def score(self, graph: FlowGraph, device="cpu") -> np.ndarray:
        """Score d'anomalie par arête (plus BAS = plus anormal)."""
        emb = self._embeddings(graph, device)
        return self.iso.score_samples(emb)

    def predict_anomaly(self, graph: FlowGraph, device="cpu") -> np.ndarray:
        """True = anomalie (potentiel VPN/Tor)."""
        emb = self._embeddings(graph, device)
        return self.iso.predict(emb) == -1
