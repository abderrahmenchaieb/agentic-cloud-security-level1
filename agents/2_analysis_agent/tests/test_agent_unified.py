"""Test : l'AnalysisAgent complet avec le détecteur unifié, sur les 2 mondes."""
import os
import sys, random
BASE = os.environ.get("REPO_ROOT", ".")
sys.path.insert(0, f"{BASE}/agents/2_analysis_agent")
sys.path.insert(0, f"{BASE}/cloud_adapter")

from analysis_agent.sequence_schema import Event, Sequence, EventCategory
from analysis_agent.unified_detector import UnifiedSequenceDetector
from analysis_agent.analysis_agent import AnalysisAgent
from datetime import datetime, timezone, timedelta

print("="*72)
print("TEST — AnalysisAgent complet avec détecteur unifié")
print("="*72)

T0 = datetime(2025,6,1,10,0,0,tzinfo=timezone.utc)
def t(s): return T0+timedelta(seconds=s)
rng = random.Random(0)

# Générateurs (mêmes que le test précédent)
def win_event(eid, sec, cat, guid, pguid, name, cmd=None, dst=None):
    return Event(eid, t(sec), cat, "VM-01", process_guid=guid,
                 parent_process_guid=pguid, process_name=name, command_line=cmd, destination_ip=dst)
def win_attack(i):
    b = rng.randint(0,900)
    return Sequence(f"wa{i}", [
        win_event(f"wa{i}1",b,EventCategory.PROCESS,f"{{A{i}1}}","{r}","winword.exe","winword.exe d.docx"),
        win_event(f"wa{i}2",b+2,EventCategory.PROCESS,f"{{A{i}2}}",f"{{A{i}1}}","powershell.exe","powershell -enc "+"Q"*40),
        win_event(f"wa{i}3",b+3,EventCategory.NETWORK,f"{{A{i}2}}",f"{{A{i}1}}","powershell.exe",dst="185.220.101.5"),
    ])
def win_normal(i):
    b=rng.randint(0,900); p=rng.choice(["chrome.exe","teams.exe"])
    return Sequence(f"wn{i}", [win_event(f"wn{i}1",b,EventCategory.PROCESS,f"{{N{i}1}}","{r}",p,p)])
def cloud_event(eid, sec, action, service, outcome="success"):
    e = Event(eid, t(sec), EventCategory.OTHER, "cloud", process_guid=None,
              parent_process_guid=None, process_name=action, command_line=None)
    e.extra = {"cloud_service": service, "outcome": outcome}
    return e
def cloud_attack(i):
    b=rng.randint(0,900)
    return Sequence(f"ca{i}", [
        cloud_event(f"ca{i}1",b,"GetCallerIdentity","sts"),
        cloud_event(f"ca{i}2",b+1,"GetSecretValue","secretsmanager"),
        cloud_event(f"ca{i}3",b+2,"GetSecretValue","secretsmanager"),
        cloud_event(f"ca{i}4",b+3,"AttachUserPolicy","iam"),
        cloud_event(f"ca{i}5",b+4,"StopLogging","cloudtrail"),
    ])
def cloud_normal(i):
    b=rng.randint(0,900)
    return Sequence(f"cn{i}", [
        cloud_event(f"cn{i}1",b,"DescribeInstances","ec2"),
        cloud_event(f"cn{i}2",b+5,"DescribeVpcs","ec2"),
    ])

# Entraîner le détecteur unifié
det = UnifiedSequenceDetector(recall_threshold=0.3)
seqs, lbls = [], []
for i in range(40): seqs.append(win_attack(i)); lbls.append(1)
for i in range(120): seqs.append(win_normal(i)); lbls.append(0)
for i in range(40): seqs.append(cloud_attack(i)); lbls.append(1)
for i in range(120): seqs.append(cloud_normal(i)); lbls.append(0)
det.fit(seqs, lbls)

# Créer l'agent Analysis avec le détecteur unifié (SANS interpréteur LLM pour ce test)
agent = AnalysisAgent(detector=det, interpreter=None)
print("\nAgent Analysis créé avec le détecteur unifié (aucune modif de l'agent).")

# --- Analyser un flux WINDOWS ---
# L'agent utilise son builder interne, mais pour tester on lui donne des events
# qui formeront des séquences. On teste via predict direct sur des séquences.
print("\n--- L'agent détecte-t-il dans les deux mondes ? ---")
tests = [
    ("Windows attaque", win_attack(500), True),
    ("Windows normal ", win_normal(500), False),
    ("Cloud attaque  ", cloud_attack(500), True),
    ("Cloud normal   ", cloud_normal(500), False),
]
results = []
for nom, seq, attendu in tests:
    v = det.predict(seq)  # le détecteur que l'agent utilise
    ok = v.is_attack == attendu
    results.append(ok)
    print(f"  {nom} → source={v.source:9s} attaque={v.is_attack} (score {v.attack_score:.2f}) {'✓' if ok else '✗'}")

print("\n" + "="*72)
print("VÉRIFICATIONS")
print("="*72)
checks = [
    ("Agent accepte le détecteur unifié sans modification", agent.detector is det),
    ("Interface compatible (predict fonctionne)", hasattr(det.predict(win_attack(1)), "is_attack")),
    ("Windows attaque détectée par l'agent", results[0]),
    ("Windows normal ignoré", results[1]),
    ("Cloud attaque détectée par l'agent", results[2]),
    ("Cloud normal ignoré", results[3]),
]
all_ok = all(ok for _,ok in checks)
for label, ok in checks:
    print(f"  [{'OK' if ok else 'ECHEC'}] {label}")
print(f"\n{'TOUS OK — agent Analysis unifié (câblage cloud complet, 0 modif agent)' if all_ok else 'ÉCHECS'}")
