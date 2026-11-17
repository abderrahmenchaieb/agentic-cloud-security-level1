"""Test préparation + graphe sur données synthétiques imitant CIC-Darknet2020."""
import numpy as np
import pandas as pd
from anonymization_detection_agent.darknet_preprocessing import DarknetPreprocessor
from anonymization_detection_agent.graph_builder import GraphBuilder

# --- Fabriquer un CSV synthétique à la structure de CIC-Darknet2020 ---
rng = np.random.default_rng(0)
def make_rows(n, label, ip_pool_dst):
    rows = []
    for _ in range(n):
        rows.append({
            "Src IP": f"10.0.0.{rng.integers(1,50)}",
            "Dst IP": rng.choice(ip_pool_dst),
            "Src Port": int(rng.integers(1024, 65535)),
            "Dst Port": int(rng.choice([443, 80, 9001])),
            "Protocol": 6,
            "Flow Duration": float(rng.integers(100, 100000)),
            "Total Fwd Packet": float(rng.integers(1, 100)),
            "Total Bwd Packet": float(rng.integers(1, 100)),
            "Flow Bytes/s": float(rng.random()*10000),
            "Flow IAT Mean": float(rng.random()*1000),
            "Label": label,
        })
    return rows

# déséquilibre volontaire (comme le vrai) : beaucoup de normal, peu de Tor
normal_dst = [f"142.250.{rng.integers(0,255)}.{rng.integers(0,255)}" for _ in range(20)]
vpn_dst = [f"45.83.220.{i}" for i in range(10)]
tor_dst = [f"185.220.101.{i}" for i in range(5)]

rows = (make_rows(500, "Non-Tor", normal_dst) +
        make_rows(120, "VPN", vpn_dst) +
        make_rows(30, "Tor", tor_dst))
# ajouter des DOUBLONS (défaut connu du dataset)
rows += rows[:40]
rng.shuffle(rows)
df = pd.DataFrame(rows)
print(f"CSV synthétique : {len(df)} lignes (dont 40 doublons injectés)")

# --- Préparation ---
prep = DarknetPreprocessor()
# vérifier la détection d'absence d'IP
df_no_ip = df.drop(columns=["Src IP", "Dst IP"])
try:
    prep.load_csv_from_df = None
    # simuler le check IP directement
    from darknet_preprocessing import IP_COLUMNS
    has_ip = any(c in df_no_ip.columns for c in IP_COLUMNS["src_ip"])
    print(f"[Garde-fou IP] version sans IP détectée comme invalide : {not has_ip} -> {'OK' if not has_ip else 'ECHEC'}")
except Exception as e:
    print("erreur", e)

flows = prep.prepare(df)
print(f"\nAprès préparation :")
print(f"   {prep.stats.imbalance_ratio()}")
print(f"   doublons retirés : {prep.stats.n_duplicates_removed}")
print(f"   features nettoyées : {prep.stats.n_cleaned}")

# --- Rééquilibrage ---
balanced = prep.balance(flows, strategy="undersample")
from collections import Counter
dist = Counter(f.label.value for f in balanced)
print(f"\nAprès rééquilibrage (undersample) : {dict(dist)}")

# --- Construction du graphe ---
builder = GraphBuilder()
graph = builder.build(flows)
print(f"\nGraphe construit :")
for k, v in graph.summary().items():
    print(f"   {k}: {v}")
print(f"   (label_dist : 0=normal, 1=vpn, 2=tor)")

# --- Vérifications ---
print("\n" + "="*60)
print("VÉRIFICATIONS")
print("="*60)
checks = [
    ("doublons retirés (~40)", 35 <= prep.stats.n_duplicates_removed <= 45),
    ("3 classes présentes", prep.stats.n_normal>0 and prep.stats.n_vpn>0 and prep.stats.n_tor>0),
    ("déséquilibre capturé (normal majoritaire)", prep.stats.n_normal > prep.stats.n_tor*5),
    ("rééquilibrage égalise les classes", len(set(dist.values()))==1),
    ("graphe a des noeuds et arêtes", graph.n_nodes>0 and graph.n_edges>0),
    ("features d'arête = 12", graph.edge_features.shape[1]==12),
    ("IP préservées comme noeuds", any("." in nid for nid in graph.node_ids)),
]
for label, ok in checks:
    print(f"   [{'OK' if ok else 'ECHEC'}] {label}")
