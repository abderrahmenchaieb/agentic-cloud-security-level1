"""Test couche agentique Anonymization : cascade décidée + signalement proactif."""
import os
import sys
sys.path.insert(0, os.environ.get("REPO_ROOT", ".") + "/agents/3_anonymization_detection_agent")

from agentic_layer import AgentBus, AgentRequest, AgentResponse, RequestType
from anonymization_detection_agent import (NetworkFlow, FlowFeatures,
    AnonymizationLabel, LookupEngine, TorExitList, VpnRangeDb,
    AnonymizationDetectionAgent)
from agentic_layer import AgenticAnonymizationAgent, AgenticAnonymizationConfig

# ---- récepteur côté Analysis : capte les hints d'attention ----
hints_received = []
def analysis_attention_handler(req: AgentRequest) -> AgentResponse:
    hints_received.append(req.payload)
    return AgentResponse(request_id=req.request_id, responder="analysis", success=True,
                         detail=f"hint reçu: surveiller {req.payload.get('host')} "
                                f"({req.payload.get('anonymization')})")

bus = AgentBus()
bus.register(RequestType.ATTENTION_HINT, analysis_attention_handler, "analysis")

# ---- monter l'Anonymization agentique ----
TOR_IP = "185.220.101.47"
tor_list = TorExitList(); tor_list.add(TOR_IP)
lookup = LookupEngine(tor_list=tor_list, vpn_db=VpnRangeDb())
# cœur SANS GNN (mode lookup) — la cascade s'arrête au lookup pour les IP connues
core = AnonymizationDetectionAgent(lookup=lookup)
anon = AgenticAnonymizationAgent(core, bus, lookup_engine=lookup)

print("="*72)
print("TEST — Anonymization agentique : cascade décidée + hint proactif")
print("="*72)

flows = [
    # flux Tor CONNU → le lookup suffit (certain), pas besoin du GNN
    NetworkFlow(flow_id="f1", src_ip="10.0.0.5", dst_ip=TOR_IP, dst_port=443,
                protocol="tcp", features=FlowFeatures()),
    # flux normal (IP publique quelconque, inconnue) → lookup ne tranche pas
    NetworkFlow(flow_id="f2", src_ip="10.0.0.5", dst_ip="8.8.8.8", dst_port=443,
                protocol="tcp", features=FlowFeatures()),
]
flow_host_map = {"f1": "VM-07", "f2": "VM-07"}

print("\n--- Analyse agentique (cascade décidée par flux) ---")
verdicts = anon.analyze_batch(flows, flow_host_map=flow_host_map)

print("\n--- Verdicts ---")
for v in verdicts:
    print(f"    {v.flow_id}: {getattr(v.label,'value',v.label)} "
          f"(conf {v.confidence:.2f}, méthode {v.method})")

print("\n--- Effort de calcul engagé (allocation adaptative) ---")
for e in anon.effort_report():
    print(f"    {e['flow_id']}: étapes={e['stages']} → {e['label']} ({e['confidence']})")

print("\n--- Hints d'attention envoyés à l'Analysis (signalement proactif) ---")
for h in hints_received:
    print(f"    → surveiller {h.get('host')} : {h.get('anonymization')} "
          f"sur {h.get('external_ip')} (conf {h.get('confidence'):.2f})")

print("\n--- Journal du bus ---")
for i in bus.interactions():
    print(f"    {i['from']} → {i['to']} [{i['type']}]: {i['detail']}")

print("\n"+"="*72)
print("VÉRIFICATIONS")
print("="*72)
f1_effort = next((e for e in anon.effort_report() if e["flow_id"]=="f1"), None)
checks = [
    ("Flux Tor connu tranché au LOOKUP (cascade s'arrête)",
     f1_effort and f1_effort["stages"]==["lookup"]),
    ("Flux Tor correctement identifié", f1_effort and f1_effort["label"]=="tor"),
    ("Effort adaptatif tracé (allocation par flux)", len(anon.effort_report())==2),
    ("Hint proactif envoyé à l'Analysis pour le Tor", len(hints_received) >= 1),
    ("Le hint concerne le bon host (VM-07)",
     any(h.get("host")=="VM-07" for h in hints_received)),
    ("Coopération tracée sur le bus",
     any(i['type']=='attention_hint' for i in bus.interactions())),
]
all_ok = True
for label, ok in checks:
    all_ok = all_ok and ok
    print(f"  [{'OK' if ok else 'ECHEC'}] {label}")
print(f"\n{'TOUS OK — Anonymization est agentique' if all_ok else 'ÉCHECS'}")
