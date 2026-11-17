#!/usr/bin/env python3
"""Exemple minimal : l'Analysis Agent sur une attaque + du bruit."""
from datetime import datetime, timezone, timedelta
from analysis_agent import (Event, EventCategory, Sequence, SequenceBuilder,
    SequenceDetector, MitreRAG, InterpretationEngine, AnalysisAgent)
from analysis_agent.mitre_sample import SAMPLE_TECHNIQUES

T0 = datetime(2025,6,1,10,0,0,tzinfo=timezone.utc)
def t(s): return T0+timedelta(seconds=s)
def E(eid,sec,cat,guid,pguid,name,cmd=None,dst=None):
    return Event(eid,t(sec),cat,"VM-01",process_guid=guid,parent_process_guid=pguid,
                 process_name=name,command_line=cmd,destination_ip=dst)

# --- entraînement minimal de l'Étage 1 ---
import random; rng=random.Random(0)
def atk(i):
    b=rng.randint(0,900)
    return Sequence(f"a{i}",[E(f"a{i}1",b,EventCategory.PROCESS,f"{{A{i}1}}","{r}","winword.exe","winword.exe d.docx"),
        E(f"a{i}2",b+2,EventCategory.PROCESS,f"{{A{i}2}}",f"{{A{i}1}}","powershell.exe","powershell -enc "+"Q"*40),
        E(f"a{i}3",b+3,EventCategory.NETWORK,f"{{A{i}2}}",f"{{A{i}1}}","powershell.exe",dst="185.220.101.5"),
        E(f"a{i}4",b+6,EventCategory.PROCESS,f"{{A{i}3}}",f"{{A{i}2}}","whoami.exe","whoami /priv")])
def nrm(i):
    b=rng.randint(0,900);p=rng.choice(["chrome.exe","teams.exe"])
    return Sequence(f"n{i}",[E(f"n{i}1",b,EventCategory.PROCESS,f"{{N{i}1}}","{r}",p,p)])
train=[atk(i) for i in range(40)]+[nrm(i) for i in range(160)]
detector=SequenceDetector(recall_threshold=0.3).fit(train,[1]*40+[0]*160)

# --- RAG + LLM simulé (remplace par OllamaLLM en vrai) ---
rag=MitreRAG(); rag.index(SAMPLE_TECHNIQUES)
class DemoLLM:
    def generate(self,p):
        return '{"hypothesis":"Document lanca un PowerShell encode vers un C2, puis reconnaissance.","techniques":[{"technique_id":"T1059.001","confidence":"high"},{"technique_id":"T1071.001","confidence":"medium"},{"technique_id":"T1033","confidence":"high"}]}'
agent=AnalysisAgent(detector=detector,interpreter=InterpretationEngine(DemoLLM(),rag))

# --- flux d'entrée : une attaque + du bruit ---
events=[]
for e in atk(999).events: events.append(e)
for e in nrm(999).events: events.append(e)

out=agent.analyze(events)
print("Stats:",out.stats)
for v in out.attacks():
    print(f"\n[ATTAQUE] {v.sequence_id} (score {v.attack_score:.2f})")
    print(f"  processus : {' -> '.join(v.sequence_summary['processes'])}")
    print(f"  hypothese : {v.hypothesis}")
    for tt in v.techniques:
        print(f"    [{tt.technique_id}] {tt.name} ({tt.tactic}) — {tt.confidence}")
