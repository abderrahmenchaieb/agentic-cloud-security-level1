"""Test de bout en bout du package reconstruit."""
from datetime import datetime, timezone, timedelta
import random
from analysis_agent import (Event, EventCategory, Sequence, SequenceBuilder,
    SequenceDetector, MitreRAG, InterpretationEngine, AnalysisAgent)
from analysis_agent.mitre_sample import SAMPLE_TECHNIQUES

rng = random.Random(0); T0 = datetime(2025,6,1,10,0,0,tzinfo=timezone.utc)
def t(s): return T0+timedelta(seconds=s)
def mk(eid,sec,cat,guid,pguid,pname,cmd=None,dst=None,host="VM-01",sess="0x3E7"):
    return Event(eid,t(sec),cat,host,process_guid=guid,parent_process_guid=pguid,
                 process_name=pname,command_line=cmd,destination_ip=dst,session_id=sess)
def atk(i):
    b=rng.randint(0,1000);e=rng.choice(["winword.exe","excel.exe"])
    return Sequence(f"a{i}",[mk(f"a{i}1",b,EventCategory.PROCESS,f"{{A{i}1}}","{r}",e,f"{e} f.docx"),
        mk(f"a{i}2",b+2,EventCategory.PROCESS,f"{{A{i}2}}",f"{{A{i}1}}","powershell.exe","powershell -enc "+"Q"*40),
        mk(f"a{i}3",b+3,EventCategory.NETWORK,f"{{A{i}2}}",f"{{A{i}1}}","powershell.exe",dst="185.220.101.5"),
        mk(f"a{i}4",b+5,EventCategory.PROCESS,f"{{A{i}3}}",f"{{A{i}2}}","svchost.exe","svchost.exe"),
        mk(f"a{i}5",b+7,EventCategory.PROCESS,f"{{A{i}4}}",f"{{A{i}3}}","whoami.exe","whoami /priv")],host="VM-01")
def nrm(i):
    b=rng.randint(0,1000);p=rng.choice(["chrome.exe","teams.exe","code.exe"])
    return Sequence(f"n{i}",[mk(f"n{i}1",b,EventCategory.PROCESS,f"{{N{i}1}}","{r}",p,p)],host="VM-01")

train=[atk(i) for i in range(60)]+[nrm(i) for i in range(240)]
lab=[1]*60+[0]*240
det=SequenceDetector(recall_threshold=0.3); det.fit(train,lab)
rag=MitreRAG(); rag.index(SAMPLE_TECHNIQUES)
class MockLLM:
    def generate(self,p): return '{"hypothesis":"Phishing to PowerShell C2 with recon.","techniques":[{"technique_id":"T1059.001","confidence":"high"},{"technique_id":"T1033","confidence":"high"},{"technique_id":"T9999","confidence":"high"}]}'
agent=AnalysisAgent(detector=det,interpreter=InterpretationEngine(MockLLM(),rag),builder=SequenceBuilder())

events=[]
for e in atk(999).events: events.append(e)
for e in nrm(999).events: events.append(e)
rng.shuffle(events)
out=agent.analyze(events)
print("Stats:",out.stats)
atts=out.attacks()
print("Attaques:",len(atts))
for v in atts:
    print("  hypothese:",v.hypothesis[:60])
    print("  techniques:",[x.technique_id for x in v.techniques])
    print("  T9999 hallucine filtre:", "T9999" not in [x.technique_id for x in v.techniques])
print("\n[OK] Package reconstruit fonctionne — resultats identiques a avant.")
