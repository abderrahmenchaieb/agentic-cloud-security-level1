"""Test de la détection de gaps (suppression de logs)."""
from datetime import datetime, timezone, timedelta
from collect_agent.gap_detection import GapDetectionEngine

T0 = datetime(2025, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
KEY = "VM-01:sysmon"

print("=" * 60)
print("A. DETECTION PAR SAUT DE RECORDNUMBER")
print("=" * 60)
engine = GapDetectionEngine()
# flux normal : 100, 101, 102, puis SAUT à 106 (103,104,105 supprimes), puis 107
records = [100, 101, 102, 106, 107]
for i, rec in enumerate(records):
    findings = engine.analyze_log(KEY, rec, T0 + timedelta(seconds=i))
    gap = [f for f in findings if f.gap_type.value == "record_gap"]
    if gap:
        print(f"  RecordNumber #{rec} : [GAP DETECTE] {gap[0].detail} (severite {gap[0].severity_score:.2f})")
    else:
        print(f"  RecordNumber #{rec} : normal")

print("\n" + "=" * 60)
print("B. DETECTION PAR SILENCE ANORMAL (source qui emet regulierement)")
print("=" * 60)
engine2 = GapDetectionEngine()
# la source emet toutes les ~2s (rythme regulier), puis un TROU de 60s
t = T0
intervals = [2, 2, 2, 2, 2, 2, 2, 60]  # les 7 premiers = normal, le dernier = anormal
rec = 200
for i, dt in enumerate(intervals):
    t = t + timedelta(seconds=dt)
    rec += 1
    findings = engine2.analyze_log(KEY, rec, t)
    sil = [f for f in findings if f.gap_type.value == "silence_gap"]
    if sil:
        print(f"  +{dt:>2}s : [GAP DETECTE] {sil[0].detail} (severite {sil[0].severity_score:.2f})")
    else:
        print(f"  +{dt:>2}s : normal (rythme appris)")

print("\n" + "=" * 60)
print("C. DETECTION D'UNE SOURCE COUPEE (check periodique)")
print("=" * 60)
engine3 = GapDetectionEngine()
# source emet toutes les 2s pendant un moment
t = T0
rec = 300
for i in range(8):
    t = t + timedelta(seconds=2)
    rec += 1
    engine3.analyze_log(KEY, rec, t)
print(f"  Source active jusqu'a t={t.strftime('%H:%M:%S')}, rythme ~2s appris")
# ... puis plus rien. On verifie le silence 90s plus tard (attaquant a coupe la source)
check_time = t + timedelta(seconds=90)
findings = engine3.check_silence(check_time)
if findings:
    for f in findings:
        print(f"  [SOURCE COUPEE DETECTEE] a t+90s : {f.detail}")
        print(f"                           severite {f.severity_score:.2f}")
else:
    print("  [RATE] source coupee non detectee")

print("\n" + "=" * 60)
print("D. CONTROLE : pas de faux positif sur un flux regulier")
print("=" * 60)
engine4 = GapDetectionEngine()
t = T0; rec = 400; fp = 0
for i in range(20):
    t = t + timedelta(seconds=2)  # parfaitement regulier
    rec += 1  # numeros consecutifs
    findings = engine4.analyze_log(KEY, rec, t)
    if findings:
        fp += 1
print(f"  20 logs reguliers et consecutifs : {fp} faux positif(s) -> {'OK' if fp == 0 else 'ECHEC'}")
