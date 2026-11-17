"""Test : le GNN E-GraphSAGE apprend-il à séparer normal/VPN/Tor ?"""
import numpy as np
import torch
from anonymization_detection_agent.flow_schema import NetworkFlow, FlowFeatures, AnonymizationLabel
from anonymization_detection_agent.graph_builder import GraphBuilder
from anonymization_detection_agent.egraphsage import train_egraphsage, graph_to_tensors, EGraphSAGE
from sklearn.metrics import classification_report, f1_score

rng = np.random.default_rng(0)
torch.manual_seed(0)

# --- Générer des flux où chaque classe a une SIGNATURE de features distincte ---
# (dans le vrai dataset, ces signatures existent : Tor a des patterns typiques)
def make_flow(i, label):
    if label == AnonymizationLabel.NORMAL:
        dur, fwd, bwd, iat = rng.normal(5000,1500), rng.normal(50,15), rng.normal(48,15), rng.normal(200,60)
        dst = f"142.250.{rng.integers(0,255)}.{rng.integers(0,255)}"
    elif label == AnonymizationLabel.VPN:
        # VPN : ressemble au normal mais un peu différent (DUR à séparer, comme en vrai)
        dur, fwd, bwd, iat = rng.normal(6000,1800), rng.normal(45,18), rng.normal(52,18), rng.normal(230,70)
        dst = f"45.83.220.{rng.integers(0,255)}"
    else:  # TOR : signature bien distincte (FACILE, comme en vrai)
        dur, fwd, bwd, iat = rng.normal(15000,3000), rng.normal(120,25), rng.normal(20,8), rng.normal(600,120)
        dst = f"185.220.101.{rng.integers(0,255)}"
    feats = FlowFeatures(
        flow_duration=max(1,dur), total_fwd_packets=max(1,fwd), total_bwd_packets=max(1,bwd),
        flow_iat_mean=max(1,iat), flow_bytes_per_s=rng.random()*10000,
        down_up_ratio=bwd/max(1,fwd))
    return NetworkFlow(flow_id=f"f{i}", src_ip=f"10.0.0.{rng.integers(1,40)}", dst_ip=dst,
                       features=feats, label=label)

flows = []
i = 0
for _ in range(600): flows.append(make_flow(i, AnonymizationLabel.NORMAL)); i+=1
for _ in range(300): flows.append(make_flow(i, AnonymizationLabel.VPN)); i+=1
for _ in range(200): flows.append(make_flow(i, AnonymizationLabel.TOR)); i+=1
rng.shuffle(flows)

# --- Graphe ---
graph = GraphBuilder().build(flows)
print("Graphe:", graph.summary())

# --- Masques train/val/test (sur les arêtes) ---
n = graph.n_edges
idx = rng.permutation(n)
tr, va = int(0.6*n), int(0.8*n)
train_mask = np.zeros(n, bool); train_mask[idx[:tr]] = True
val_mask   = np.zeros(n, bool); val_mask[idx[tr:va]] = True
test_mask  = np.zeros(n, bool); test_mask[idx[va:]] = True

# --- Poids de classe (gérer le déséquilibre) ---
counts = np.bincount(graph.edge_labels, minlength=3)
class_weights = (counts.sum() / (3 * np.maximum(counts,1))).tolist()
print(f"Poids de classe (normal,vpn,tor): {[f'{w:.2f}' for w in class_weights]}\n")

print("Entraînement E-GraphSAGE:")
model = train_egraphsage(graph, train_mask, val_mask, epochs=100, lr=0.01,
                         class_weights=class_weights, verbose=True)

# --- Évaluation sur le test, PAR CLASSE (Tor et VPN séparés !) ---
edge_index, edge_feat, edge_labels = graph_to_tensors(graph)
model.eval()
with torch.no_grad():
    pred = model(edge_index, edge_feat, graph.n_nodes).argmax(1).numpy()
y_true = graph.edge_labels[test_mask]
y_pred = pred[test_mask]

print("\n" + "="*60)
print("ÉVALUATION PAR CLASSE (Tor et VPN mesurés SÉPARÉMENT)")
print("="*60)
names = ["normal","vpn","tor"]
print(classification_report(y_true, y_pred, target_names=names, digits=3, zero_division=0))

f1_per = f1_score(y_true, y_pred, average=None, labels=[0,1,2], zero_division=0)
print(f"F1 normal : {f1_per[0]:.3f}")
print(f"F1 VPN    : {f1_per[1]:.3f}   <- la tâche DURE")
print(f"F1 Tor    : {f1_per[2]:.3f}   <- la tâche FACILE")
print(f"\nConstat attendu : Tor mieux détecté que VPN (comme la littérature).")
