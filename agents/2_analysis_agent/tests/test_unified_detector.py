"""Test du détecteur unifié : routage + détection dans les deux mondes."""
import os
import sys, random
BASE = os.environ.get("REPO_ROOT", ".")
sys.path.insert(0, f"{BASE}/agents/2_analysis_agent")
sys.path.insert(0, f"{BASE}/cloud_adapter")

from analysis_agent.sequence_schema import Event, Sequence, EventCategory
from analysis_agent.unified_detector import UnifiedSequenceDetector, _detect_source
from datetime import datetime, timezone, timedelta

print("="*72)
print("TEST — Détecteur unifié (routage Windows/Cloud + détection)")
print("="*72)

T0 = datetime(2025,6,1,10,0,0,tzinfo=timezone.utc)
def t(s): return T0+timedelta(seconds=s)
rng = random.Random(0)

# --- Générateurs WINDOWS (comme dans l'exemple Analysis existant) ---
def win_event(eid, sec, cat, guid, pguid, name, cmd=None, dst=None):
    return Event(eid, t(sec), cat, "VM-01", process_guid=guid,
                 parent_process_guid=pguid, process_name=name,
                 command_line=cmd, destination_ip=dst)

def win_attack(i):
    b = rng.randint(0,900)
    return Sequence(f"wa{i}", [
        win_event(f"wa{i}1",b,EventCategory.PROCESS,f"{{A{i}1}}","{r}","winword.exe","winword.exe d.docx"),
        win_event(f"wa{i}2",b+2,EventCategory.PROCESS,f"{{A{i}2}}",f"{{A{i}1}}","powershell.exe","powershell -enc "+"Q"*40),
        win_event(f"wa{i}3",b+3,EventCategory.NETWORK,f"{{A{i}2}}",f"{{A{i}1}}","powershell.exe",dst="185.220.101.5"),
        win_event(f"wa{i}4",b+6,EventCategory.PROCESS,f"{{A{i}3}}",f"{{A{i}2}}","whoami.exe","whoami /priv"),
    ])
def win_normal(i):
    b = rng.randint(0,900); p = rng.choice(["chrome.exe","teams.exe"])
    return Sequence(f"wn{i}", [win_event(f"wn{i}1",b,EventCategory.PROCESS,f"{{N{i}1}}","{r}",p,p)])

# --- Générateurs CLOUD (événements avec cloud_service dans extra) ---
def cloud_event(eid, sec, action, service, outcome="success"):
    e = Event(eid, t(sec), EventCategory.OTHER, "cloud", process_guid=None,
              parent_process_guid=None, process_name=action, command_line=None)
    e.extra = {"cloud_service": service, "outcome": outcome}
    return e

def cloud_attack(i):
    b = rng.randint(0,900)
    return Sequence(f"ca{i}", [
        cloud_event(f"ca{i}1",b,"GetCallerIdentity","sts"),
        cloud_event(f"ca{i}2",b+1,"ListSecrets","secretsmanager"),
        cloud_event(f"ca{i}3",b+2,"GetSecretValue","secretsmanager"),
        cloud_event(f"ca{i}4",b+3,"GetSecretValue","secretsmanager"),
        cloud_event(f"ca{i}5",b+4,"AttachUserPolicy","iam"),
        cloud_event(f"ca{i}6",b+5,"CreateAccessKey","iam"),
        cloud_event(f"ca{i}7",b+6,"StopLogging","cloudtrail"),
    ])
def cloud_normal(i):
    b = rng.randint(0,900)
    return Sequence(f"cn{i}", [
        cloud_event(f"cn{i}1",b,"DescribeInstances","ec2"),
        cloud_event(f"cn{i}2",b+5,"DescribeVpcs","ec2"),
        cloud_event(f"cn{i}3",b+10,"ListTagsForResource","ec2"),
    ])

# --- Test du ROUTAGE d'abord ---
print("\n--- Routage (détection de source) ---")
wa, ca = win_attack(0), cloud_attack(0)
print(f"  Séquence Windows → source détectée : {_detect_source(wa)}")
print(f"  Séquence Cloud   → source détectée : {_detect_source(ca)}")

# --- Entraînement unifié (mélange Windows + Cloud) ---
print("\n--- Entraînement unifié (mélange des deux mondes) ---")
train_seqs, train_lbls = [], []
for i in range(40): train_seqs.append(win_attack(i)); train_lbls.append(1)
for i in range(120): train_seqs.append(win_normal(i)); train_lbls.append(0)
for i in range(40): train_seqs.append(cloud_attack(i)); train_lbls.append(1)
for i in range(120): train_seqs.append(cloud_normal(i)); train_lbls.append(0)

det = UnifiedSequenceDetector(recall_threshold=0.3)
det.fit(train_seqs, train_lbls)
print(f"  Entraîné sur {len(train_seqs)} séquences (Windows + Cloud mélangés)")

# --- Prédictions sur des cas de test ---
print("\n--- Prédictions (les deux mondes) ---")
tests = [
    ("Windows attaque", win_attack(999), True),
    ("Windows normal", win_normal(999), False),
    ("Cloud attaque", cloud_attack(999), True),
    ("Cloud normal", cloud_normal(999), False),
]
results = []
for nom, seq, attendu in tests:
    v = det.predict(seq)
    ok = v.is_attack == attendu
    results.append((nom, v, attendu, ok))
    print(f"  {nom:18s} → source={v.source:9s} attaque={v.is_attack} "
          f"(score {v.attack_score:.2f}) attendu={attendu} {'✓' if ok else '✗'}")

print("\n" + "="*72)
print("VÉRIFICATIONS")
print("="*72)
checks = [
    ("Routage Windows correct", _detect_source(wa) == "endpoint"),
    ("Routage Cloud correct", _detect_source(ca) == "cloud"),
    ("Windows attaque détectée", results[0][1].is_attack),
    ("Windows normal → pas d'alerte", not results[1][1].is_attack),
    ("Cloud attaque détectée", results[2][1].is_attack),
    ("Cloud normal → pas d'alerte", not results[3][1].is_attack),
    ("Windows routé vers voie endpoint", results[0][1].source == "endpoint"),
    ("Cloud routé vers voie cloud", results[2][1].source == "cloud"),
    ("Interface unique (une seule classe predict)", hasattr(det, "predict")),
]
all_ok = all(ok for _,ok in checks)
for label, ok in checks:
    print(f"  [{'OK' if ok else 'ECHEC'}] {label}")
print(f"\n{'TOUS OK — détecteur unifié fonctionnel (routage + 2 mondes)' if all_ok else 'ÉCHECS'}")
