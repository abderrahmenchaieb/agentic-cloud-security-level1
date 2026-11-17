"""Test bout-en-bout : CloudTrail brut → adaptateur → Collect Agent (intégrité)."""
import os
import sys, json
sys.path.insert(0, os.environ.get("REPO_ROOT", ".") + "/agents/1_collect_agent")
from cloud_adapter import AwsCloudTrailAdapter
from collect_agent.collect_agent import CollectAgent
from cloud_adapter import process_canonical_logs

def evt(eid, sec, source, name, ip="185.220.101.47", err=None):
    e = {"eventVersion":"1.09","eventTime":f"2024-03-06T21:{sec:02d}:00Z",
         "eventSource":f"{source}.amazonaws.com","eventName":name,
         "awsRegion":"us-east-1","sourceIPAddress":ip,"userAgent":"aws-cli/2.13",
         "eventID":str(eid),
         "userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::999:user/stolen",
             "accountId":"999","userName":"stolen","accessKeyId":"AKIA_X",
             "sessionContext":{"attributes":{"creationDate":"2024-03-06T21:20:00Z"}}}}
    if err: e["errorCode"] = err
    return e

cloudtrail = {"Records":[
    evt(100, 22, "sts", "GetCallerIdentity"),
    evt(101, 23, "iam", "ListUsers"),
    evt(105, 27, "s3",  "GetObject"),          # saut 101→105 (102-104 supprimés)
    evt(106, 28, "cloudtrail", "StopLogging"),
    evt(107, 29, "iam", "DeleteUser", err="AccessDenied"),
]}

print("="*72)
print("TEST BOUT-EN-BOUT : CloudTrail → Adaptateur → Collect Agent")
print("="*72)
adapter = AwsCloudTrailAdapter()
canonical = adapter.parse(json.dumps(cloudtrail))
print(f"\n[1] Adaptateur : {len(cloudtrail['Records'])} CloudTrail → {len(canonical)} canonique")

collect = CollectAgent()
outputs = process_canonical_logs(collect, canonical)
print(f"[2] Collect Agent (intégrité cloud) : {collect.stats}")
print(f"\n    Gaps détectés (suppression de logs) :")
for g in outputs.gaps:
    print(f"      - {g.detail}")
print(f"\n    Événements enriched :")
for e in outputs.enriched:
    flags = [a.detail for a in e.annotations]
    print(f"      [{e.log.event_time.strftime('%H:%M:%S')}] {e.log.action_name}"
          + (" ⚠️" if flags else ""))
    for f in flags: print(f"          → {f}")

print("\n"+"="*72); print("VÉRIFICATIONS"); print("="*72)
checks = [
    ("Adaptateur → 5 logs canoniques", len(canonical)==5),
    ("Collect a traité les logs cloud", collect.stats["processed"]==5),
    ("GAP détecté (logs supprimés)", len(outputs.gaps) > 0),
    ("StopLogging présent (surveillable)", any(e.log.action_name=="StopLogging" for e in outputs.enriched)),
    ("IP préservée pour Anonymization", all(e.log.actor.source_ip=="185.220.101.47" for e in outputs.enriched)),
    ("Aucun rejet à tort", len(outputs.rejected)==0),
]
all_ok = all(ok for _,ok in checks)
for label, ok in checks: print(f"  [{'OK' if ok else 'ECHEC'}] {label}")
print(f"\n{'TOUS OK — le Collect Agent traite le cloud' if all_ok else 'ÉCHECS'}")
