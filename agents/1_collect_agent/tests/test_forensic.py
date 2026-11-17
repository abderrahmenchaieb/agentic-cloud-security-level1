"""Test des règles forensiques : logs authentiques vs falsifiés."""
from datetime import datetime, timezone, timedelta
from collect_agent.canonical_schema import CanonicalLog, SourceType, ActivityCategory, Outcome, ProcessContext
from collect_agent.forensic_rules import ForensicRuleEngine

NOW = datetime(2025, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

def make_log(event_time, ingest_time=None, guid="{g-1}", parent_guid="{g-0}", host="VM-01"):
    return CanonicalLog(
        source_type=SourceType.ENDPOINT, source_provider="sysmon",
        event_time=event_time, ingest_time=ingest_time or NOW,
        activity=ActivityCategory.PROCESS, action_name="ProcessCreate",
        outcome=Outcome.SUCCESS, host=host,
        process_context=ProcessContext(process_guid=guid, parent_process_guid=parent_guid),
    )

engine = ForensicRuleEngine()

print("=" * 60)
print("1. LOGS AUTHENTIQUES (ne doivent RIEN declencher)")
print("=" * 60)
# flux normal, ordonné, timestamps plausibles
authentiques = [
    make_log(NOW - timedelta(seconds=10), guid="{g-1}", parent_guid="{g-0}"),
    make_log(NOW - timedelta(seconds=5),  guid="{g-2}", parent_guid="{g-1}"),
    make_log(NOW - timedelta(seconds=1),  guid="{g-3}", parent_guid="{g-2}"),
]
clean = True
for log in authentiques:
    findings = engine.analyze(log)
    if findings:
        clean = False
        print(f"  [PROBLEME] faux positif: {[f.rule_id for f in findings]}")
print(f"  Resultat: {'OK - aucun faux positif' if clean else 'ECHEC'}")

print("\n" + "=" * 60)
print("2. FALSIFICATIONS (doivent etre detectees)")
print("=" * 60)

engine2 = ForensicRuleEngine()

cas = {
    "MODIFICATION - timestomping (1970)":
        make_log(datetime(1970, 1, 1, tzinfo=timezone.utc)),
    "MODIFICATION - timestamp futur":
        make_log(NOW + timedelta(hours=2)),
    "INJECTION - clock skew enorme (event il y a 3 jours)":
        make_log(NOW - timedelta(days=3), ingest_time=NOW),
    "INJECTION - processus son propre parent":
        make_log(NOW, guid="{g-X}", parent_guid="{g-X}"),
}
for nom, log in cas.items():
    findings = engine2.analyze(log)
    if findings:
        for f in findings:
            print(f"  [DETECTE] {nom}")
            print(f"            -> {f.rule_id} ({f.tamper_type.value}, {f.confidence})")
            print(f"            -> {f.detail}")
    else:
        print(f"  [RATE!] {nom} -> non detecte")

print("\n" + "=" * 60)
print("3. REORDONNANCEMENT (flux dont l'ordre chronologique est casse)")
print("=" * 60)
engine3 = ForensicRuleEngine()
flux_reordonne = [
    make_log(NOW - timedelta(seconds=10), guid="{s-1}"),
    make_log(NOW - timedelta(seconds=5),  guid="{s-2}"),
    make_log(NOW - timedelta(seconds=8),  guid="{s-3}"),  # RECUL temporel = anomalie
]
for i, log in enumerate(flux_reordonne):
    findings = engine3.analyze(log)
    tag = "normal" if not findings else f"DETECTE: {[f.rule_id for f in findings]}"
    print(f"  log #{i} (t={log.event_time.strftime('%H:%M:%S')}): {tag}")
