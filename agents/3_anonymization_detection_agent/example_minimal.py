#!/usr/bin/env python3
"""Exemple minimal : le Anonymization Detection Agent (lookup seul, sans GNN entraîné)."""
from anonymization_detection_agent import (
    AnonymizationDetectionAgent, LookupEngine, TorExitList, VpnRangeDb, NetworkFlow,
)

# Sources de lookup
tor = TorExitList(); tor.load(["185.220.101.99", "204.13.164.118"])
vpn = VpnRangeDb(); vpn.add_range("45.83.220.0/22")
agent = AnonymizationDetectionAgent(lookup=LookupEngine(tor_list=tor, vpn_db=vpn))

# Flux à analyser
flows = [
    NetworkFlow(flow_id="tor",     src_ip="10.0.0.5", dst_ip="185.220.101.99"),
    NetworkFlow(flow_id="vpn",     src_ip="10.0.0.5", dst_ip="45.83.220.10"),
    NetworkFlow(flow_id="inconnu", src_ip="10.0.0.5", dst_ip="8.8.8.8"),
]

for v in agent.analyze_batch(flows):
    print(f"[{v.flow_id:8}] {v.label.value:8} via {v.method:8} (conf {v.confidence:.2f}) — {v.detail}")

print("\nNote : le flux 'inconnu' sort en UNKNOWN car aucun GNN n'est branché ici.")
print("Avec un E-GraphSAGE entraîné, il serait classé normal/VPN/Tor par le GNN.")
