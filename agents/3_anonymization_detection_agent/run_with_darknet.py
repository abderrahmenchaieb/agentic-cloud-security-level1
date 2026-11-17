#!/usr/bin/env python3
"""
Point d'entrée : brancher CIC-Darknet2020 sur le Anonymization Detection Agent.

Workflow complet avec de VRAIES données :
  1. charger le CSV BRUT de CIC-Darknet2020 (avec les IP !)
  2. préparer : nettoyer, dédupliquer, mesurer le déséquilibre
  3. construire le graphe de flux
  4. entraîner E-GraphSAGE (supervisé) — le moteur de décision
  5. entraîner Anomal-E (self-supervised) — pour l'ablation anti-circularité
  6. ÉVALUER en séparant Tor et VPN (jamais agréger !)

IMPORTANT : utilise le fichier BRUT (Darknet.csv) qui contient Src IP / Dst IP.
Les versions "preprocessed" de Kaggle suppriment les IP → graphe impossible.

Usage : python run_with_darknet.py /chemin/vers/Darknet.csv
"""
import sys
import numpy as np

from anonymization_detection_agent import (
    DarknetPreprocessor, GraphBuilder,
    train_egraphsage, train_anomale, AnomalEDetector, graph_to_tensors,
)


def main(csv_path: str):
    import torch
    from sklearn.metrics import classification_report, roc_auc_score, f1_score

    print(f"[1] Chargement de CIC-Darknet2020 (brut) : {csv_path}")
    prep = DarknetPreprocessor()
    df = prep.load_csv(csv_path)   # lève une erreur si les IP manquent
    print(f"    {len(df)} lignes, {len(df.columns)} colonnes")

    print("[2] Préparation (nettoyage, déduplication) ...")
    flows = prep.prepare(df)
    print(f"    {prep.stats.imbalance_ratio()}")
    print(f"    doublons retirés : {prep.stats.n_duplicates_removed}")

    print("[3] Construction du graphe ...")
    graph = GraphBuilder().build(flows, normalize=True)
    print(f"    {graph.summary()}")

    # masques train/val/test sur les arêtes
    n = graph.n_edges
    rng = np.random.default_rng(42)
    idx = rng.permutation(n)
    tr, va = int(0.6 * n), int(0.8 * n)
    train_mask = np.zeros(n, bool); train_mask[idx[:tr]] = True
    val_mask   = np.zeros(n, bool); val_mask[idx[tr:va]] = True
    test_mask  = np.zeros(n, bool); test_mask[idx[va:]] = True

    counts = np.bincount(graph.edge_labels, minlength=3)
    class_weights = (counts.sum() / (3 * np.maximum(counts, 1))).tolist()

    print("[4] Entraînement E-GraphSAGE (supervisé) ...")
    model = train_egraphsage(graph, train_mask, val_mask, epochs=200,
                             class_weights=class_weights, verbose=True)

    print("[5] Entraînement Anomal-E (self-supervised, sans labels) ...")
    dgi = train_anomale(graph, epochs=150, verbose=True)
    anomale = AnomalEDetector(dgi, contamination=0.15)
    anomale.fit(graph, normal_mask=(graph.edge_labels == 0))

    print("[6] ÉVALUATION (Tor et VPN SÉPARÉS) ...")
    evaluate(graph, model, anomale, test_mask)


def evaluate(graph, model, anomale, test_mask):
    import torch
    from sklearn.metrics import classification_report, roc_auc_score, f1_score

    edge_index, edge_feat, _ = graph_to_tensors(graph)
    model.eval()
    with torch.no_grad():
        pred = model(edge_index, edge_feat, graph.n_nodes).argmax(1).numpy()

    y_true = graph.edge_labels[test_mask]
    y_pred = pred[test_mask]

    print("\n--- E-GraphSAGE (supervisé) ---")
    print(classification_report(y_true, y_pred, target_names=["normal", "vpn", "tor"],
                                digits=3, zero_division=0))
    f1 = f1_score(y_true, y_pred, average=None, labels=[0, 1, 2], zero_division=0)
    print(f"F1 Tor : {f1[2]:.3f}  (tâche facile)")
    print(f"F1 VPN : {f1[1]:.3f}  (tâche DURE)")

    print("\n--- Anomal-E (self-supervised, ablation anti-circularité) ---")
    scores = anomale.score(graph)
    labels = graph.edge_labels
    is_anon = (labels != 0).astype(int)
    auroc = roc_auc_score(is_anon, -scores)
    tor_m = (labels == 2) | (labels == 0)
    vpn_m = (labels == 1) | (labels == 0)
    print(f"AUROC global      : {auroc:.3f}")
    print(f"AUROC Tor         : {roc_auc_score((labels[tor_m]==2).astype(int), -scores[tor_m]):.3f}")
    print(f"AUROC VPN         : {roc_auc_score((labels[vpn_m]==1).astype(int), -scores[vpn_m]):.3f}")
    print("\n→ Comparer supervisé vs self-supervised : si proches, le self-supervised")
    print("  atteint presque le supervisé SANS labels (argument anti-circularité).")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python run_with_darknet.py /chemin/vers/Darknet.csv")
        print("  (le fichier BRUT avec les colonnes Src IP / Dst IP)")
        sys.exit(1)
    main(sys.argv[1])
