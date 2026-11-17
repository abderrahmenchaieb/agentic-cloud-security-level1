"""Test : l'interpréteur MITRE sait-il nommer une attaque CLOUD ?"""
import os
import sys
BASE = os.environ.get("REPO_ROOT", ".")
sys.path.insert(0, f"{BASE}/agents/2_analysis_agent")
sys.path.insert(0, f"{BASE}/cloud_adapter")
sys.path.insert(0, f"{BASE}/agents/1_collect_agent")

from analysis_agent.mitre_rag import MitreRAG
from analysis_agent.mitre_sample import SAMPLE_TECHNIQUES
from cloud_adapter.mitre_cloud_sample import SAMPLE_CLOUD_TECHNIQUES
from analysis_agent.sequence_schema import Event, Sequence, EventCategory
from analysis_agent.interpretation_engine import InterpretationEngine
from datetime import datetime, timezone, timedelta

print("="*72)
print("TEST — Interpréteur MITRE sur attaque cloud")
print("="*72)

# Construire une séquence d'attaque cloud
T0 = datetime(2025,6,1,10,0,0,tzinfo=timezone.utc)
def t(s): return T0+timedelta(seconds=s)
def cev(eid, sec, action, service):
    e = Event(eid, t(sec), EventCategory.OTHER, "cloud", process_guid=None,
              parent_process_guid=None, process_name=action, command_line=None)
    e.extra = {"cloud_service": service, "outcome": "success"}
    return e
cloud_seq = Sequence("cloud-atk", [
    cev("1",0,"GetCallerIdentity","sts"),
    cev("2",1,"GetSecretValue","secretsmanager"),
    cev("3",2,"AttachUserPolicy","iam"),
    cev("4",3,"StopLogging","cloudtrail"),
])

# LLM simulé qui renvoie des techniques cloud (comme le ferait Ollama)
class CloudLLM:
    def generate(self, prompt):
        # il choisit parmi les candidats du RAG
        return '''{"hypothesis":"Compromission d'identité cloud: vol de secrets, escalade IAM, désactivation des logs.",
        "techniques":[{"technique_id":"T1098.001","confidence":"high"},
                      {"technique_id":"T1562.008","confidence":"high"}]}'''

# --- Scénario A : RAG avec SEULEMENT les techniques Windows (le trou) ---
print("\n--- A. RAG Windows seul (ne connaît pas le cloud) ---")
rag_win = MitreRAG(); rag_win.index(SAMPLE_TECHNIQUES)
interp_win = InterpretationEngine(CloudLLM(), rag_win)
res_a = interp_win.interpret(cloud_seq)
print(f"  Techniques trouvées : {[t.technique_id for t in res_a.techniques]}")
print(f"  → {'VIDE (le trou !)' if not res_a.techniques else 'des techniques'}")

# --- Scénario B : RAG avec Windows + Cloud (le trou comblé) ---
print("\n--- B. RAG unifié Windows + Cloud ---")
rag_all = MitreRAG(); rag_all.index(SAMPLE_TECHNIQUES + SAMPLE_CLOUD_TECHNIQUES)
interp_all = InterpretationEngine(CloudLLM(), rag_all)
res_b = interp_all.interpret(cloud_seq)
print(f"  Techniques trouvées : {[t.technique_id for t in res_b.techniques]}")
for tq in res_b.techniques:
    print(f"    {tq.technique_id} | {tq.name} | {tq.tactic}")

print("\n" + "="*72)
print("VÉRIFICATIONS")
print("="*72)
tids_b = [t.technique_id for t in res_b.techniques]
checks = [
    ("RAG Windows seul → ne nomme PAS les techniques cloud (le trou)", len(res_a.techniques) == 0),
    ("RAG unifié → nomme des techniques cloud", len(res_b.techniques) > 0),
    ("RAG unifié → au moins une technique cloud nommée", any(t in tids_b for t in ["T1098.001","T1562.008","T1548.005","T1078.004"])),
    ("RAG unifié → T1562.008 (disable cloud logs) reconnue", "T1562.008" in tids_b),
    ("13 techniques cloud disponibles dans le sample", len(SAMPLE_CLOUD_TECHNIQUES) == 13),
]
all_ok = all(ok for _,ok in checks)
for label, ok in checks:
    print(f"  [{'OK' if ok else 'ECHEC'}] {label}")
print(f"\n{'TOUS OK — interpréteur cloud fonctionne si le RAG est unifié' if all_ok else 'ÉCHECS'}")
print("\n>>> CONCLUSION : il faut indexer SAMPLE_TECHNIQUES + SAMPLE_CLOUD_TECHNIQUES")
print(">>> ensemble dans le RAG de l'Analysis pour couvrir les deux mondes.")
