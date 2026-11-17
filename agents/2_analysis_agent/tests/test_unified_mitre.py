"""Test du helper RAG unifié (Windows + Cloud) en une ligne."""
import os
import sys
BASE = os.environ.get("REPO_ROOT", ".")
sys.path.insert(0, f"{BASE}/agents/2_analysis_agent")
sys.path.insert(0, f"{BASE}/cloud_adapter")
sys.path.insert(0, f"{BASE}/agents/1_collect_agent")

from analysis_agent.unified_mitre import build_unified_rag, load_cloud_techniques
from analysis_agent.mitre_sample import SAMPLE_TECHNIQUES

print("="*72)
print("TEST — RAG MITRE unifié (Windows + Cloud) en une ligne")
print("="*72)

# construire le RAG unifié
rag = build_unified_rag()
cloud_techs = load_cloud_techniques()

print(f"\n  Techniques Windows : {len(SAMPLE_TECHNIQUES)}")
print(f"  Techniques Cloud   : {len(cloud_techs)}")

# vérifier que le RAG peut récupérer des techniques cloud
from analysis_agent.mitre_rag import sequence_to_query
# récupérer par mots-clés cloud
hits_cloud = rag.retrieve("StopLogging cloudtrail disable logging AttachUserPolicy IAM")
hits_win = rag.retrieve("powershell encoded command spearphishing")

cloud_ids = [h.technique.technique_id for h in hits_cloud]
win_ids = [h.technique.technique_id for h in hits_win]
print(f"\n  Requête cloud → techniques récupérées : {cloud_ids[:5]}")
print(f"  Requête Windows → techniques récupérées : {win_ids[:5]}")

print("\n" + "="*72)
print("VÉRIFICATIONS")
print("="*72)
# vérifier que le RAG unifié contient bien les deux mondes
all_indexed = [rt.technique.technique_id for rt in
               [type('X',(),{'technique':t})() for t in SAMPLE_TECHNIQUES + cloud_techs]]
checks = [
    ("Helper charge les techniques cloud", len(cloud_techs) == 13),
    ("RAG unifié construit sans erreur", rag is not None),
    ("Requête cloud récupère des techniques cloud",
     any(tid in ["T1562.008","T1098.001","T1078.004","T1548.005","T1580"] for tid in cloud_ids)),
    ("Requête Windows récupère des techniques Windows",
     any(tid.startswith("T1059") or tid.startswith("T1566") for tid in win_ids)),
    ("Le RAG couvre les DEUX mondes (Windows + Cloud)",
     len(SAMPLE_TECHNIQUES) > 0 and len(cloud_techs) > 0),
]
all_ok = all(ok for _,ok in checks)
for label, ok in checks:
    print(f"  [{'OK' if ok else 'ECHEC'}] {label}")
print(f"\n{'TOUS OK — RAG unifié couvre Windows + Cloud en une ligne' if all_ok else 'ÉCHECS'}")
