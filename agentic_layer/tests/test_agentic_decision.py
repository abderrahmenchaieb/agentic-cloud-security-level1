"""Test couche agentique Decision : exécution outillée + re-sollicitation."""
import os
import sys
sys.path.insert(0, os.environ.get("REPO_ROOT", ".") + "/agents/4_decision_agent")

from dataclasses import dataclass, field
from agentic_layer import AgentBus, AgentRequest, AgentResponse, RequestType
from decision_agent import DecisionAgent, ActionGenerator, DefenseKnowledgeBase
from agentic_layer import (AgenticDecisionAgent, AgenticDecisionConfig,
    ActionPolicy)

# structures des sorties amont
@dataclass
class ThreatVerdict:
    host: str; is_attack: bool; attack_score: float
    hypothesis: str=""; techniques: list=field(default_factory=list)
    sequence_summary: dict=field(default_factory=dict)
    observed_artifacts: list=field(default_factory=list)
@dataclass
class AnonVerdict:
    flow_id: str; external_ip: str; label: str; confidence: float

# ---- outils exécutables réels (simulés) ----
executed_tools = []
def block_ip(host, payload):
    executed_tools.append(("block_ip", host)); return f"IP bloquée sur {host}"
def isolate_host(host, payload):
    executed_tools.append(("isolate", host)); return f"{host} isolé du réseau"

tools = {"D3-OTF": block_ip, "D3-NTA": isolate_host}

# ---- récepteur REANALYZE côté Analysis (simule une ré-analyse qui lève le doute) ----
def analysis_reanalyze_handler(req: AgentRequest) -> AgentResponse:
    host = req.payload.get("host")
    # simulate : la ré-analyse approfondie conclut que c'était bénin
    return AgentResponse(request_id=req.request_id, responder="analysis", success=True,
        payload={"attack_score": 0.2, "resolved": True},
        detail=f"ré-analyse de {host}: activité bénigne confirmée (faux positif)")

class DecisionLLM:
    def generate(self, p):
        return '{"summary":"Attaque confirmée, contenir.","actions":[{"action_id":"D3-OTF","priority":"immediate","reason":"bloquer C2"},{"action_id":"D3-NTA","priority":"high","reason":"analyser"}]}'

bus = AgentBus()
bus.register(RequestType.REANALYZE, analysis_reanalyze_handler, "analysis")

core = DecisionAgent(action_generator=ActionGenerator(DecisionLLM(), DefenseKnowledgeBase()))
decision = AgenticDecisionAgent(core, bus, tools=tools,
    config=AgenticDecisionConfig(policy=ActionPolicy.AUTO_IMMEDIATE_ONLY))

print("="*72)
print("TEST — Decision agentique : exécution outillée + re-sollicitation")
print("="*72)

# ---- Cas A : attaque CONFIRMÉE → exécution des actions ----
print("\n--- Cas A : attaque confirmée sur VM-01 (score 0.92) ---")
outA = decision.decide(
    threat_verdicts=[ThreatVerdict(host="VM-01", is_attack=True, attack_score=0.92,
        hypothesis="C2 confirmé", techniques=[{"id":"T1059.001"},{"id":"T1071.001"}],
        sequence_summary={"external_ips":["1.2.3.4"]},
        observed_artifacts=["process","network_traffic"])],
)
print("\n  Actions exécutées:")
for e in decision.execution_report():
    status = "EXÉCUTÉE" if e["executed"] else f"non exécutée ({e['reason']})"
    print(f"    {e['action_id']} ({e['name']}): {status}"
          + (f" — {e['result']}" if e['executed'] else ""))

# ---- Cas B : cas DOUTEUX → re-sollicitation avant escalade ----
print("\n--- Cas B : menace ambiguë sur VM-05 (score 0.45) → doute ---")
outB = decision.decide(
    threat_verdicts=[ThreatVerdict(host="VM-05", is_attack=True, attack_score=0.45,
        hypothesis="activité suspecte non concluante", techniques=[{"id":"T1059.001"}],
        sequence_summary={"external_ips":[]}, observed_artifacts=["process"])],
)
vm05 = next((o for o in outB.outcomes if o.decision.host=="VM-05"), None)
print(f"\n  Après re-sollicitation:")
print(f"    escalade finale: {vm05.decision.escalate} (dossier N2: {vm05.level2_dossier is not None})")
for r in decision.reassessment_report():
    print(f"    ré-analyse: {r['detail']} → doute résolu: {r['resolved']}")

print("\n--- Journal du bus ---")
for i in bus.interactions():
    print(f"    {i['from']} → {i['to']} [{i['type']}]: {i['detail']}")

print("\n"+"="*72)
print("VÉRIFICATIONS")
print("="*72)
exec_report = decision.execution_report()
otf = next((e for e in exec_report if e["action_id"]=="D3-OTF"), None)
nta = next((e for e in exec_report if e["action_id"]=="D3-NTA"), None)
checks = [
    ("Action 'immediate' (D3-OTF) EXÉCUTÉE via outil", otf and otf["executed"]),
    ("Outil de blocage réellement appelé", ("block_ip","VM-01") in executed_tools),
    ("Action 'high' (D3-NTA) NON auto-exécutée (politique immediate_only)",
     nta and not nta["executed"]),
    ("Cas douteux → ré-analyse demandée (perception active)",
     any(i['type']=='reanalyze' for i in bus.interactions())),
    ("Doute levé localement → escalade Niveau 2 ÉVITÉE",
     vm05 and not vm05.decision.escalate),
    ("Décision agentique tracée", len(decision.reassessment_report()) >= 1),
]
all_ok = True
for label, ok in checks:
    all_ok = all_ok and ok
    print(f"  [{'OK' if ok else 'ECHEC'}] {label}")
print(f"\n{'TOUS OK — Decision est agentique' if all_ok else 'ÉCHECS'}")
