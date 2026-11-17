"""Test du RAG MITRE for Cloud sur les étapes d'une attaque cloud."""
import os
import sys, json
sys.path.insert(0, os.environ.get("REPO_ROOT", ".") + "/agents/1_collect_agent")
sys.path.insert(0, os.environ.get("REPO_ROOT", ".") + "/agents/2_analysis_agent")
from analysis_agent.mitre_rag import MitreRAG, sequence_to_query
from cloud_adapter import SAMPLE_CLOUD_TECHNIQUES
from cloud_adapter import AwsCloudTrailAdapter, canonical_to_cloud_events, CloudSequenceBuilder

print("="*72)
print("TEST — RAG MITRE for Cloud")
print("="*72)

# indexer les techniques cloud
rag = MitreRAG()
rag.index(SAMPLE_CLOUD_TECHNIQUES)
print(f"\n{len(SAMPLE_CLOUD_TECHNIQUES)} techniques cloud indexées")

# --- vérifier la récupération pour chaque étape d'attaque ---
print("\n--- Récupération par type d'action (top-3) ---")
test_queries = [
    ("credentials volés / identité", "GetCallerIdentity stolen access key cloud account", "T1078.004"),
    ("énumération utilisateurs", "ListUsers iam enumeration account discovery", "T1087.004"),
    ("escalade IAM", "AttachUserPolicy AdministratorAccess privilege escalation", "T1548.005"),
    ("exfiltration S3", "GetObject s3 bucket sensitive data", "T1530"),
    ("désactivation logs", "StopLogging disable cloudtrail cover tracks", "T1562.008"),
    ("création clé d'accès", "CreateAccessKey add credentials persistence", "T1098.001"),
]
hits = 0
for label, query, expected in test_queries:
    results = rag.retrieve(query, k=3)
    top_ids = [r.technique.technique_id for r in results]
    found = expected in top_ids
    hits += found
    rank = top_ids.index(expected)+1 if found else "-"
    print(f"  [{'OK' if found else '  '}] {label:28} → {expected} (rang {rank}) | top: {top_ids}")

# --- test sur une VRAIE séquence cloud (via le pipeline complet) ---
print("\n--- Sur une séquence d'attaque cloud réelle (via le pipeline) ---")
def evt(eid, sec, source, name, ip="185.220.101.47"):
    return {"eventVersion":"1.09","eventTime":f"2024-03-06T21:{sec:02d}:00Z",
        "eventSource":f"{source}.amazonaws.com","eventName":name,"awsRegion":"us-east-1",
        "sourceIPAddress":ip,"userAgent":"aws-cli","eventID":str(eid),
        "userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::999:user/alice","accountId":"999",
            "userName":"alice","accessKeyId":"AKIA_X",
            "sessionContext":{"attributes":{"creationDate":"SESS-A"}}}}
cloudtrail = {"Records":[
    evt(1,20,"sts","GetCallerIdentity"), evt(2,21,"iam","ListUsers"),
    evt(3,22,"iam","AttachUserPolicy"), evt(4,23,"s3","GetObject"),
    evt(5,24,"cloudtrail","StopLogging"),
]}
adapter = AwsCloudTrailAdapter()
events = canonical_to_cloud_events(adapter.parse(json.dumps(cloudtrail)))
sequences = CloudSequenceBuilder().build(events)
seq = sequences[0]
query = sequence_to_query(seq)
print(f"  séquence: {[e.process_name for e in seq.events]}")
results = rag.retrieve(query, k=6)
print(f"  techniques candidates récupérées (top-6):")
for r in results:
    print(f"     {r.technique.technique_id} | {r.technique.name} ({r.technique.tactic})")

# les techniques attendues de cette attaque
expected_set = {"T1078.004","T1087.004","T1548.005","T1530","T1562.008"}
retrieved_set = {r.technique.technique_id for r in results}
covered = expected_set & retrieved_set

print("\n" + "="*72)
print("VÉRIFICATIONS")
print("="*72)
checks = [
    ("Récupération par action: au moins 5/6 correctes", hits >= 5),
    ("Escalade IAM → T1548.005 récupérée", "T1548.005" in retrieved_set),
    ("Exfiltration → T1530 récupérée", "T1530" in retrieved_set),
    ("Désactivation logs → T1562.008 récupérée", "T1562.008" in retrieved_set),
    ("Couverture de l'attaque: >=4/5 techniques attendues dans le top-6", len(covered) >= 4),
]
all_ok = True
for label, ok in checks:
    all_ok = all_ok and ok
    print(f"  [{'OK' if ok else 'ECHEC'}] {label}")
print(f"\n  Couverture: {len(covered)}/5 techniques de l'attaque récupérées: {covered}")
print(f"\n{'TOUS OK — le RAG MITRE for Cloud fonctionne' if all_ok else 'ÉCHECS'}")
