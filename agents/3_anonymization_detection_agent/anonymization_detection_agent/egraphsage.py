# =============================================================================
# GNN E-GraphSAGE — classification de flux (arêtes)
# =============================================================================
# Implémentation de E-GraphSAGE, adaptée à la détection VPN/Tor.
#
# Spécificité E-GraphSAGE (vs GraphSAGE classique) :
#   - les FEATURES sont sur les ARÊTES (les flux), pas les nœuds
#   - l'agrégation d'un nœud collecte les features des ARÊTES incidentes
#   - la classification se fait sur les ARÊTES (embedding d'arête =
#     concaténation des embeddings des deux nœuds qu'elle relie)
#
# Les nœuds n'ont pas de features propres → vecteur constant de 1
# (le signal vient entièrement des flux).
#
# Implémenté en PyTorch pur (sans dépendance DGL/PyG) pour la portabilité.
# =============================================================================

from __future__ import annotations
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

from .graph_builder import FlowGraph


class EGraphSAGELayer(nn.Module):
    """
    Une couche E-GraphSAGE.
    Message d'une arête = concat(h_voisin, features_arête) → transformé.
    Agrégation = moyenne des messages des arêtes incidentes.
    """
    def __init__(self, node_dim: int, edge_dim: int, out_dim: int):
        super().__init__()
        # le message combine l'état du nœud voisin ET la feature de l'arête
        self.msg = nn.Linear(node_dim + edge_dim, out_dim)
        self.upd = nn.Linear(node_dim + out_dim, out_dim)

    def forward(self, h, edge_index, edge_feat):
        # h : [n_nodes, node_dim] ; edge_index : [2, n_edges] ; edge_feat : [n_edges, edge_dim]
        src, dst = edge_index
        # message porté par chaque arête (état du src + feature de l'arête)
        m = torch.cat([h[src], edge_feat], dim=1)
        m = F.relu(self.msg(m))                       # [n_edges, out_dim]

        # agrégation : chaque nœud dst reçoit la moyenne des messages entrants
        agg = torch.zeros(h.size(0), m.size(1), device=h.device)
        agg = agg.index_add(0, dst, m)
        deg = torch.zeros(h.size(0), device=h.device).index_add(
            0, dst, torch.ones(dst.size(0), device=h.device))
        deg = deg.clamp(min=1).unsqueeze(1)
        agg = agg / deg

        # mise à jour du nœud
        h_new = F.relu(self.upd(torch.cat([h, agg], dim=1)))
        return h_new


class EGraphSAGE(nn.Module):
    """
    Réseau E-GraphSAGE complet pour la classification d'arêtes (flux).
    """
    def __init__(self, edge_dim: int, hidden_dim: int = 64,
                 n_classes: int = 3, n_layers: int = 2):
        super().__init__()
        self.node_init_dim = hidden_dim
        self.layers = nn.ModuleList()
        node_dim = hidden_dim
        for i in range(n_layers):
            self.layers.append(EGraphSAGELayer(node_dim, edge_dim, hidden_dim))
            node_dim = hidden_dim
        # classifieur d'arête : concat(h_src, h_dst, edge_feat) → classe
        self.edge_classifier = nn.Sequential(
            nn.Linear(hidden_dim * 2 + edge_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim, n_classes),
        )

    def forward(self, edge_index, edge_feat, n_nodes):
        # nœuds initialisés à un vecteur constant (E-GraphSAGE : pas de features nœud)
        h = torch.ones(n_nodes, self.node_init_dim, device=edge_feat.device)
        for layer in self.layers:
            h = layer(h, edge_index, edge_feat)
        # embedding d'arête = concat des deux extrémités + feature d'arête
        src, dst = edge_index
        edge_emb = torch.cat([h[src], h[dst], edge_feat], dim=1)
        return self.edge_classifier(edge_emb)


def graph_to_tensors(graph: FlowGraph, device="cpu"):
    """Convertit un FlowGraph en tenseurs PyTorch."""
    edge_index = torch.tensor(
        np.stack([graph.edge_src, graph.edge_dst]), dtype=torch.long, device=device)
    edge_feat = torch.tensor(graph.edge_features, dtype=torch.float32, device=device)
    edge_labels = torch.tensor(graph.edge_labels, dtype=torch.long, device=device)
    return edge_index, edge_feat, edge_labels


def train_egraphsage(graph: FlowGraph, train_mask, val_mask,
                     epochs: int = 100, lr: float = 0.01,
                     n_classes: int = 3, class_weights=None, device="cpu",
                     verbose: bool = True):
    """
    Entraîne E-GraphSAGE sur les arêtes du graphe.
    train_mask / val_mask : masques booléens sur les arêtes.
    class_weights : pondération pour gérer le déséquilibre.
    """
    edge_index, edge_feat, edge_labels = graph_to_tensors(graph, device)
    model = EGraphSAGE(edge_dim=edge_feat.size(1), n_classes=n_classes).to(device)
    opt = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=5e-4)

    w = torch.tensor(class_weights, dtype=torch.float32, device=device) if class_weights is not None else None
    train_mask_t = torch.tensor(train_mask, device=device)
    val_mask_t = torch.tensor(val_mask, device=device)

    for epoch in range(epochs):
        model.train()
        opt.zero_grad()
        logits = model(edge_index, edge_feat, graph.n_nodes)
        loss = F.cross_entropy(logits[train_mask_t], edge_labels[train_mask_t], weight=w)
        loss.backward()
        opt.step()

        if verbose and (epoch + 1) % 20 == 0:
            model.eval()
            with torch.no_grad():
                pred = model(edge_index, edge_feat, graph.n_nodes).argmax(1)
                val_acc = (pred[val_mask_t] == edge_labels[val_mask_t]).float().mean().item()
            print(f"   epoch {epoch+1:3d} | loss {loss.item():.4f} | val_acc {val_acc:.3f}")

    return model
