"""Test de la couche agentique de l'Analysis + coopération réelle avec le Collect."""
import os
import sys
sys.path.insert(0, os.environ.get("REPO_ROOT", ".") + "/agents/1_collect_agent")
sys.path.insert(0, os.environ.get("REPO_ROOT", ".") + "/agents/2_analysis_agent")

from datetime import datetime, timezone, timedelta
import random
from agentic_layer import AgentBus
from collect_agent import CollectAgent
from agentic_layer import AgenticCollectAgent
from analysis_agent import (Event, EventCategory, Sequence, SequenceBuilder,
    SequenceDetector, MitreRAG, InterpretationEngine, AnalysisAgent)
from analysis_agent.sequence_builder import SequenceBuilderConfig
from analysis_agent.mitre_sample import SAMPLE_TECHNIQUES
from agentic_layer import AgenticAnalysisAgent, AgenticAnalysisConfig

# ============ entraîner le détecteur (comme d'habitude) ============
rng = random.Random(0); T0 = datetime(2025,1,1,tzinfo=timezone.utc)
def mk(eid,sec,cat,guid,pguid,pname,cmd=None,dst=None,host="VM-01"):
    return Event(eid,T0+timedelta(seconds=sec),cat,host,process_guid=guid,
        parent_process_guid=pguid,process_name=pname,command_line=cmd,destination_ip=dst)
def atk(i):
    b=rng.randint(0,900)
    return Sequence(f"a{i}",[mk(f"a{i}1",b,EventCategory.PROCESS,f"{{A{i}1}}","{r}","winword.exe","winword.exe d.docx"),
        mk(f"a{i}2",b+2,EventCategory.PROCESS,f"{{A{i}2}}",f"{{A{i}1}}","powershell.exe","powershell -enc "+"Q"*40),
        mk(f"a{i}3",b+3,EventCategory.NETWORK,f"{{A{i}2}}",f"{{A{i}1}}","powershell.exe",dst="1.2.3.4"),
        mk(f"a{i}4",b+6,EventCategory.PROCESS,f"{{A{i}3}}",f"{{A{i}2}}","whoami.exe","whoami")])
def nrm(i):
    b=rng.randint(0,900)
    return Sequence(f"n{i}",[mk(f"n{i}1",b,EventCategory.PROCESS,f"{{N{i}1}}","{r}","chrome.exe","chrome.exe")])
train=[atk(i) for i in range(40)]+[nrm(i) for i in range(160)]
detector=SequenceDetector(recall_threshold=0.5).fit(train,[1]*40+[0]*160)
rag=MitreRAG(); rag.index(SAMPLE_TECHNIQUES)
class SimLLM:
    def generate(self,p): return '{"hypothesis":"attaque tronquée","techniques":[{"technique_id":"T1059.001","confidence":"medium"}]}'

# ============ monter les 2 agents agentiques sur le MÊME bus ============
bus = AgentBus()
# Collect agentique (répond aux CHECK_GAP)
collect_core = CollectAgent()
collect = AgenticCollectAgent(collect_core, bus, recollect_source=lambda h,r: "ok")
# Analysis agentique
analysis_core = AnalysisAgent(detector=detector,
    interpreter=InterpretationEngine(SimLLM(), rag), builder=SequenceBuilder())
analysis = AgenticAnalysisAgent(analysis_core, bus,
    builder_cls=SequenceBuilder, builder_config_cls=SequenceBuilderConfig,
    config=AgenticAnalysisConfig(incomplete_max_events=3))

print("="*72)
print("TEST — Analysis agentique + COOPÉRATION avec Collect (via le bus)")
print("="*72)

# ============ ÉTAPE 1 : le Collect voit une attaque TRONQUÉE par un gap ============
print("\n--- Le Collect traite des logs : attaque tronquée (gap sur VM-07) ---")
base = "2026-07-31 10:00"
collect_logs = [
    {"EventID":1,"UtcTime":f"{base}:00.0","Computer":"VM-07","ProcessGuid":"{Q1}",
     "ProcessId":"1","Image":"powershell.exe","CommandLine":"powershell -enc AAAA",
     "ParentProcessGuid":"{Q0}","ParentImage":"winword.exe","RecordNumber":"800"},
    # SAUT 800→806 : gap (records 801-805 supprimés = l'attaquant a effacé le milieu)
    {"EventID":1,"UtcTime":f"{base}:08.0","Computer":"VM-07","ProcessGuid":"{Q2}",
     "ProcessId":"2","Image":"whoami.exe","CommandLine":"whoami",
     "ParentProcessGuid":"{Q1}","ParentImage":"powershell.exe","RecordNumber":"806"},
]
collect.process_batch(collect_logs)
print(f"    → gap mémorisé par le Collect: {collect.known_gaps.get('VM-07', [])}")

# ============ ÉTAPE 2 : l'Analysis reçoit la séquence INCOMPLÈTE ============
# (juste 2 événements : PowerShell + whoami, le milieu a été supprimé)
print("\n--- L'Analysis analyse la séquence incomplète (le milieu manque) ---")
incomplete = [
    mk("e1",0,EventCategory.PROCESS,"{Q1}","{Q0}","powershell.exe","powershell -enc AAAA",host="VM-07"),
    mk("e2",8,EventCategory.PROCESS,"{Q2}","{Q1}","whoami.exe","whoami",host="VM-07"),
]
out = analysis.analyze(incomplete)

print("\n--- Verdicts après coopération ---")
for v in out.verdicts:
    print(f"    {v.host}: is_attack={v.is_attack}, score={v.attack_score:.2f}")
    if hasattr(v,"integrity_flags") and v.integrity_flags:
        for f in v.integrity_flags:
            print(f"       flag: {f}")

print("\n--- Décisions agentiques de l'Analysis (traçabilité) ---")
for d in analysis.decisions_report():
    print(f"    {d}")

print("\n--- Journal du bus (la coopération) ---")
for i in bus.interactions():
    print(f"    {i['from']} → {i['to']} [{i['type']}]: {i['detail']}")

print("\n"+"="*72)
print("VÉRIFICATIONS")
print("="*72)
raise_decision = next((d for d in analysis.decisions_report() if d["action"]=="raise_on_gap"), None)
vm07 = next((v for v in out.verdicts if v.host=="VM-07"), None)
checks = [
    ("Analysis a demandé un gap au Collect (perception active)",
     any(i['type']=='check_gap' and i['from']=='analysis' for i in bus.interactions())),
    ("Le Collect a répondu qu'il y a un gap",
     any(i['type']=='check_gap' and 'gap(s)' in i['detail'] for i in bus.interactions())),
    ("L'Analysis a RELEVÉ sa suspicion grâce au gap", raise_decision is not None),
    ("Score augmenté après coopération",
     raise_decision and raise_decision["score_after"] > raise_decision["score_before"]),
    ("Flag de coopération ajouté au verdict",
     vm07 and any("coopération" in f for f in (vm07.integrity_flags or []))),
]
all_ok = True
for label, ok in checks:
    all_ok = all_ok and ok
    print(f"  [{'OK' if ok else 'ECHEC'}] {label}")
print(f"\n{'TOUS OK — Analysis et Collect COOPÈRENT' if all_ok else 'ÉCHECS'}")
