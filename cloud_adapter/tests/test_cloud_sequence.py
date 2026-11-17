"""Test du sequence builder cloud : corrélation par acteur/session."""
import os
import sys, json
sys.path.insert(0, os.environ.get("REPO_ROOT", ".") + "/agents/1_collect_agent")
from cloud_adapter import AwsCloudTrailAdapter
from cloud_adapter import (canonical_to_cloud_events,
    CloudSequenceBuilder, CloudSequenceBuilderConfig)

def evt(eid, sec, source, name, user, session, ip):
    return {"eventVersion":"1.09","eventTime":f"2024-03-06T21:{sec:02d}:00Z",
        "eventSource":f"{source}.amazonaws.com","eventName":name,
        "awsRegion":"us-east-1","sourceIPAddress":ip,"userAgent":"aws-cli",
        "eventID":str(eid),
        "userIdentity":{"type":"IAMUser","arn":f"arn:aws:iam::999:user/{user}",
            "accountId":"999","userName":user,"accessKeyId":f"AKIA_{user}",
            "sessionContext":{"attributes":{"creationDate":session}}}}

# DEUX attaquants mélangés dans le flux + une activité légitime
cloudtrail = {"Records":[
    # attaquant A (session S-A) : reconnaissance → escalade → exfil
    evt(1, 20, "sts", "GetCallerIdentity", "alice", "SESS-A", "185.220.101.47"),
    evt(2, 21, "iam", "ListUsers",         "alice", "SESS-A", "185.220.101.47"),
    # admin légitime (session S-ADMIN) au milieu — ne doit PAS se mélanger
    evt(3, 22, "ec2", "DescribeInstances", "admin", "SESS-ADMIN", "10.0.0.1"),
    # attaquant A continue
    evt(4, 23, "iam", "AttachUserPolicy",  "alice", "SESS-A", "185.220.101.47"),
    evt(5, 24, "s3",  "GetObject",         "alice", "SESS-A", "185.220.101.47"),
    # attaquant B (session S-B) : autre compte compromis
    evt(6, 25, "sts", "GetCallerIdentity", "bob",   "SESS-B", "45.83.220.10"),
    evt(7, 26, "iam", "CreateAccessKey",   "bob",   "SESS-B", "45.83.220.10"),
    # admin légitime continue
    evt(8, 27, "ec2", "DescribeInstances", "admin", "SESS-ADMIN", "10.0.0.1"),
]}

print("="*72)
print("TEST — Sequence Builder Cloud (corrélation par acteur/session)")
print("="*72)

# 1. CloudTrail → canonique → Event cloud
adapter = AwsCloudTrailAdapter()
canonical = adapter.parse(json.dumps(cloudtrail))
events = canonical_to_cloud_events(canonical)
print(f"\n{len(canonical)} événements CloudTrail → {len(events)} Event cloud")

# 2. builder cloud → séquences
builder = CloudSequenceBuilder(CloudSequenceBuilderConfig(time_window_seconds=900))
sequences = builder.build(events)
print(f"→ {len(sequences)} séquences (regroupées par acteur/session)\n")

for seq in sequences:
    principal = seq.host.split("/")[-1] if seq.host else "?"
    actions = [e.process_name for e in seq.events]
    session = seq.events[0].session_id
    ips = set(e.source_ip for e in seq.events)
    print(f"  Séquence [{principal} / {session}] : {len(seq.events)} actions")
    print(f"     {' → '.join(actions)}")
    print(f"     IP(s): {ips}")

print("\n" + "="*72)
print("VÉRIFICATIONS")
print("="*72)
# retrouver les séquences par principal
seq_by_user = {}
for seq in sequences:
    user = seq.host.split("/")[-1] if seq.host else "?"
    seq_by_user.setdefault(user, []).append(seq)

alice_seq = seq_by_user.get("alice", [])
bob_seq = seq_by_user.get("bob", [])
admin_seq = seq_by_user.get("admin", [])

checks = [
    ("3 séquences distinctes (alice, bob, admin)", len(sequences)==3),
    ("Attaquant alice : 1 séquence de 4 actions", len(alice_seq)==1 and len(alice_seq[0].events)==4),
    ("Attaquant bob : 1 séquence de 2 actions", len(bob_seq)==1 and len(bob_seq[0].events)==2),
    ("Admin légitime : séparé (pas mélangé aux attaquants)", len(admin_seq)==1),
    ("alice a bien son escalade + exfil groupées",
     alice_seq and set(e.process_name for e in alice_seq[0].events) >= {"AttachUserPolicy","GetObject"}),
    ("Chaque séquence a une IP cohérente (1 seule par attaquant)",
     all(len(set(e.source_ip for e in s.events))==1 for s in alice_seq+bob_seq)),
]
all_ok = True
for label, ok in checks:
    all_ok = all_ok and ok
    print(f"  [{'OK' if ok else 'ECHEC'}] {label}")
print(f"\n{'TOUS OK — la corrélation cloud fonctionne' if all_ok else 'ÉCHECS'}")
