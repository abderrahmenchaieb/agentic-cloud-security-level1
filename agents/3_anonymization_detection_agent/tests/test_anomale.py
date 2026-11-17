"""Test Anomal-E : détecte-t-il VPN/Tor SANS jamais voir les labels ?"""
import numpy as np, torch
from anonymization_detection_agent.flow_schema import NetworkFlow, FlowFeatures, AnonymizationLabel
from anonymization_detection_agent.graph_builder import GraphBuilder
from anonymization_detection_agent.anomale import train_anomale, AnomalEDetector
from sklearn.metrics import roc_auc_score

rng = np.random.default_rng(1); torch.manual_seed(1)

def make_flow(i, label):
    if label == AnonymizationLabel.NORMAL:
        dur,fwd,bwd,iat = rng.normal(5000,1500),rng.normal(50,15),rng.normal(48,15),rng.normal(200,60)
        dst=f"142.250.{rng.integers(0,255)}.{rng.integers(0,255)}"
    elif label == AnonymizationLabel.VPN:
        dur,fwd,bwd,iat = rng.normal(6000,1800),rng.normal(45,18),rng.normal(52,18),rng.normal(230,70)
        dst=f"45.83.220.{rng.integers(0,255)}"
    else:
        dur,fwd,bwd,iat = rng.normal(15000,3000),rng.normal(120,25),rng.normal(20,8),rng.normal(600,120)
        dst=f"185.220.101.{rng.integers(0,255)}"
    feats=FlowFeatures(flow_duration=max(1,dur),total_fwd_packets=max(1,fwd),
        total_bwd_packets=max(1,bwd),flow_iat_mean=max(1,iat),
        flow_bytes_per_s=rng.random()*10000,down_up_ratio=bwd/max(1,fwd))
    return NetworkFlow(flow_id=f"f{i}",src_ip=f"10.0.0.{rng.integers(1,40)}",dst_ip=dst,features=feats,label=label)

flows=[]; i=0
for _ in range(600): flows.append(make_flow(i,AnonymizationLabel.NORMAL)); i+=1
for _ in range(300): flows.append(make_flow(i,AnonymizationLabel.VPN)); i+=1
for _ in range(200): flows.append(make_flow(i,AnonymizationLabel.TOR)); i+=1
rng.shuffle(flows)

graph = GraphBuilder().build(flows)
labels = graph.edge_labels
print("Graphe:", graph.summary())

# masque du NORMAL (pour entraîner l'IsolationForest sur le normal pur)
# NOTE : on utilise le label ICI seulement pour SÉLECTIONNER le corpus normal
# d'entraînement du détecteur — l'encodeur DGI, lui, n'utilise aucun label.
normal_mask = (labels == 0)

print("\nEntraînement Anomal-E (self-supervised, SANS labels pour l'encodeur):")
dgi = train_anomale(graph, epochs=100, verbose=True)

detector = AnomalEDetector(dgi, contamination=0.15)
detector.fit(graph, normal_mask=normal_mask)

# Score d'anomalie (plus bas = plus anormal)
scores = detector.score(graph)
# vérité terrain binaire : anomalie = VPN ou Tor
is_anon = (labels != 0).astype(int)
# AUROC : le score (inversé) sépare-t-il anonymisé/normal ?
auroc = roc_auc_score(is_anon, -scores)  # -scores : plus grand = plus anormal

print("\n" + "="*60)
print("RÉSULTAT Anomal-E (détection SANS supervision)")
print("="*60)
print(f"AUROC global (anonymisé vs normal) : {auroc:.3f}")

# séparé Tor vs VPN
tor_mask = (labels==2)|(labels==0)
vpn_mask = (labels==1)|(labels==0)
auroc_tor = roc_auc_score((labels[tor_mask]==2).astype(int), -scores[tor_mask])
auroc_vpn = roc_auc_score((labels[vpn_mask]==1).astype(int), -scores[vpn_mask])
print(f"AUROC Tor (vs normal)  : {auroc_tor:.3f}   <- devrait être élevé (facile)")
print(f"AUROC VPN (vs normal)  : {auroc_vpn:.3f}   <- devrait être plus bas (dur)")

print("\n" + "="*60)
print("INTÉRÊT vs E-GraphSAGE")
print("="*60)
print("Anomal-E n'a PAS utilisé les labels pour apprendre les embeddings.")
print("-> contourne la circularité : pas besoin de labels fiables.")
print("-> détecte des anomalies génériques (compensé par le lookup pour")
print("   distinguer précisément VPN de Tor).")
