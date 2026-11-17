"""Test du Anonymization Detection Agent complet : lookup + E-GraphSAGE."""
import numpy as np, torch
from anonymization_detection_agent.flow_schema import NetworkFlow, FlowFeatures, AnonymizationLabel
from anonymization_detection_agent.lookup_engine import LookupEngine, TorExitList, VpnRangeDb
from anonymization_detection_agent.graph_builder import GraphBuilder
from anonymization_detection_agent.egraphsage import train_egraphsage
from anonymization_detection_agent import AnonymizationDetectionAgent, AnonymizationDetectionConfig

rng = np.random.default_rng(2); torch.manual_seed(2)

def make_flow(i, label):
    if label==AnonymizationLabel.NORMAL:
        dur,fwd,bwd,iat=rng.normal(5000,1500),rng.normal(50,15),rng.normal(48,15),rng.normal(200,60)
        dst=f"142.250.{rng.integers(0,255)}.{rng.integers(0,255)}"
    elif label==AnonymizationLabel.VPN:
        dur,fwd,bwd,iat=rng.normal(6000,1800),rng.normal(45,18),rng.normal(52,18),rng.normal(230,70)
        dst=f"45.83.220.{rng.integers(0,255)}"
    else:
        dur,fwd,bwd,iat=rng.normal(15000,3000),rng.normal(120,25),rng.normal(20,8),rng.normal(600,120)
        dst=f"185.220.101.{rng.integers(0,255)}"
    feats=FlowFeatures(flow_duration=max(1,dur),total_fwd_packets=max(1,fwd),
        total_bwd_packets=max(1,bwd),flow_iat_mean=max(1,iat),
        flow_bytes_per_s=rng.random()*10000,down_up_ratio=bwd/max(1,fwd))
    return NetworkFlow(flow_id=f"f{i}",src_ip=f"10.0.0.{rng.integers(1,40)}",dst_ip=dst,features=feats,label=label)

# entraîner E-GraphSAGE
flows=[]; i=0
for _ in range(600): flows.append(make_flow(i,AnonymizationLabel.NORMAL)); i+=1
for _ in range(300): flows.append(make_flow(i,AnonymizationLabel.VPN)); i+=1
for _ in range(200): flows.append(make_flow(i,AnonymizationLabel.TOR)); i+=1
rng.shuffle(flows)
graph = GraphBuilder().build(flows)
n=graph.n_edges; idx=rng.permutation(n)
tr=int(0.7*n); train_mask=np.zeros(n,bool); train_mask[idx[:tr]]=True
val_mask=np.zeros(n,bool); val_mask[idx[tr:]]=True
counts=np.bincount(graph.edge_labels,minlength=3); cw=(counts.sum()/(3*np.maximum(counts,1))).tolist()
print("Entraînement E-GraphSAGE (bref)...")
model = train_egraphsage(graph, train_mask, val_mask, epochs=80, class_weights=cw, verbose=False)
print("  fait.\n")

# --- Configurer l'agent ---
tor = TorExitList(); tor.load(["185.220.101.99"])  # UN nœud Tor connu du lookup
vpn = VpnRangeDb(); vpn.add_range("45.83.220.0/22")  # plage VPN connue du lookup
lookup = LookupEngine(tor_list=tor, vpn_db=vpn)
agent = AnonymizationDetectionAgent(lookup=lookup, egraphsage_model=model, graph_builder=GraphBuilder())

# --- Lot de test mixte ---
test_flows = [
    # connu du lookup (Tor)
    NetworkFlow(flow_id="T-known", src_ip="10.0.0.5", dst_ip="185.220.101.99",
                features=make_flow(999,AnonymizationLabel.TOR).features, label=AnonymizationLabel.TOR),
    # connu du lookup (VPN par plage)
    NetworkFlow(flow_id="V-known", src_ip="10.0.0.5", dst_ip="45.83.220.50",
                features=make_flow(998,AnonymizationLabel.VPN).features, label=AnonymizationLabel.VPN),
    # INCONNU du lookup → GNN (Tor par signature, IP non listée)
    NetworkFlow(flow_id="T-gnn", src_ip="10.0.0.6", dst_ip="200.1.2.3",
                features=make_flow(997,AnonymizationLabel.TOR).features, label=AnonymizationLabel.TOR),
    # INCONNU → GNN (normal)
    NetworkFlow(flow_id="N-gnn", src_ip="10.0.0.7", dst_ip="8.8.4.4",
                features=make_flow(996,AnonymizationLabel.NORMAL).features, label=AnonymizationLabel.NORMAL),
    # INCONNU → GNN (VPN par signature)
    NetworkFlow(flow_id="V-gnn", src_ip="10.0.0.8", dst_ip="91.5.6.7",
                features=make_flow(995,AnonymizationLabel.VPN).features, label=AnonymizationLabel.VPN),
]

verdicts = agent.analyze_batch(test_flows)

print("="*70)
print("VERDICTS DE L'AGENT (lookup + E-GraphSAGE)")
print("="*70)
for v, f in zip(verdicts, test_flows):
    correct = "✓" if v.label==f.label else "✗"
    print(f"{correct} [{v.flow_id:9}] attendu={f.label.value:7} → prédit={v.label.value:7} "
          f"(conf {v.confidence:.2f}, {v.method})")
    print(f"              {v.detail}")

print("\n" + "="*70)
print("RÉSUMÉ")
print("="*70)
s = agent.summarize(verdicts)
print(f"  {s}")

print("\nVÉRIFICATIONS")
checks = [
    ("Tor connu → lookup", verdicts[0].method=="lookup" and verdicts[0].label==AnonymizationLabel.TOR),
    ("VPN connu → lookup", verdicts[1].method=="lookup" and verdicts[1].label==AnonymizationLabel.VPN),
    ("Flux inconnus → GNN", all(v.method=="gnn_supervised" for v in verdicts[2:])),
    ("Tor par GNN correct", verdicts[2].label==AnonymizationLabel.TOR),
]
for label, ok in checks:
    print(f"  [{'OK' if ok else 'ECHEC'}] {label}")
