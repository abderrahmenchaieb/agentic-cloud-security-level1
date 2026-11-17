#!/usr/bin/env python3
"""Exemple minimal : le Collect Agent sur un petit flux mixte."""
from datetime import datetime, timezone
from collect_agent import CollectAgent

# timestamps proches de maintenant (évite un clock-skew artificiel en démo)
now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")

flux = [
    # normal
    {"EventID":1,"UtcTime":f"{now}:00.100","Computer":"VM-01","ProcessGuid":"{g-001}",
     "Image":"explorer.exe","CommandLine":"explorer.exe","ParentProcessGuid":"{g-000}","RecordNumber":"100"},
    # réseau → flow
    {"EventID":3,"UtcTime":f"{now}:02.200","Computer":"VM-01","ProcessGuid":"{g-002}","Image":"chrome.exe",
     "SourceIp":"10.0.0.5","DestinationIp":"185.220.101.47","DestinationPort":"443","Protocol":"tcp","RecordNumber":"101"},
    # malformé → rejected
    {"EventID":1,"UtcTime":f"{now}:03.000","Image":"cmd.exe"},
    # timestomping → tampering
    {"EventID":1,"UtcTime":"1970-01-01 00:00:00.000","Computer":"VM-01","ProcessGuid":"{g-004}",
     "Image":"evil.exe","ParentProcessGuid":"{g-001}","RecordNumber":"102"},
    # gap (102 → 106) + normal
    {"EventID":1,"UtcTime":f"{now}:08.500","Computer":"VM-01","ProcessGuid":"{g-006}",
     "Image":"svchost.exe","ParentProcessGuid":"{g-001}","RecordNumber":"106"},
]

agent = CollectAgent()
agent.process_batch(flux)

print("Résumé:", agent.outputs.summary())
print("Santé :", agent.stats)
print("\nAnnotations d'intégrité :")
for e in agent.outputs.enriched:
    for a in e.annotations:
        print(f"  {e.log.event_id[:8]} [{a.kind}] {a.detail[:55]}")
print("\nFlows →Geolocation:", [(f.source_ip, f.destination_ip) for f in agent.outputs.flows])
print("Rejected:", [r.reason for r in agent.outputs.rejected])
