"""Test de la couche agentique du Collect : vigilance adaptative + interactions."""
import os
import sys
sys.path.insert(0, os.environ.get("REPO_ROOT", ".") + "/agents/1_collect_agent")

from datetime import datetime, timezone
from collect_agent import CollectAgent
from agentic_layer import AgentBus, AgentRequest, RequestType
from agentic_layer import AgenticCollectAgent

# --- source de re-collecte réelle (simulée : accès confirmé) ---
recollect_log = []
def fake_source(host, rng):
    recollect_log.append((host, rng))
    # en vrai : rappeler la source de logs pour la plage manquante
    return f"logs {rng} récupérés depuis la source"

# --- monter l'agent agentique par-dessus le cœur ---
bus = AgentBus()
core = CollectAgent()
agent = AgenticCollectAgent(core, bus, recollect_source=fake_source)

# --- scénario : attaque avec falsification (1970) + gap (records manquants) ---
base = "2026-07-31 10:00"
logs = [
    {"EventID":1,"UtcTime":f"{base}:00.100","Computer":"VM-01","ProcessGuid":"{P1}",
     "ProcessId":"1000","Image":"winword.exe","CommandLine":"winword.exe x.docx",
     "ParentProcessGuid":"{P0}","ParentImage":"explorer.exe","RecordNumber":"500"},
    {"EventID":1,"UtcTime":f"{base}:02.000","Computer":"VM-01","ProcessGuid":"{P2}",
     "ProcessId":"2000","Image":"powershell.exe","CommandLine":"powershell -enc AAAA",
     "ParentProcessGuid":"{P1}","ParentImage":"winword.exe","RecordNumber":"501"},
    # SAUT 501→505 = gap (records 502-504 manquants)
    {"EventID":1,"UtcTime":f"{base}:05.000","Computer":"VM-01","ProcessGuid":"{P3}",
     "ProcessId":"3000","Image":"whoami.exe","CommandLine":"whoami",
     "ParentProcessGuid":"{P2}","ParentImage":"powershell.exe","RecordNumber":"505"},
    # log FALSIFIÉ : timestamp 1970
    {"EventID":1,"UtcTime":"1970-01-01 00:00:00.000","Computer":"VM-01","ProcessGuid":"{P4}",
     "Image":"evil.exe","ParentProcessGuid":"{P2}","RecordNumber":"506"},
]

print("="*70)
print("TEST — Couche agentique du Collect Agent")
print("="*70)
print("\n--- Traitement du lot (le cœur traite, la couche réagit) ---")
outputs = agent.process_batch(logs)

print(f"\n--- Sorties du cœur (inchangé) ---")
print(f"    stats: {core.stats}")
print(f"    gaps détectés: {len(outputs.gaps)}, falsifications: "
      f"{sum(1 for e in outputs.enriched for a in e.annotations if a.kind=='tampering_rule')}")

print(f"\n--- État de vigilance (auto-adaptation) ---")
for host, v in agent.vigilance_report().items():
    print(f"    {host}: {v['level']} (falsifications vues: {v['tampering_count']}, "
          f"k_sigma: {v['k_sigma']})")

print(f"\n--- Re-collectes déclenchées (action réelle) ---")
for host, rng in recollect_log:
    print(f"    re-collecte sur {host}, plage {rng}")

print(f"\n--- Interaction : un autre agent demande 'gap sur VM-01 ?' ---")
resp = bus.request(AgentRequest(
    request_type=RequestType.CHECK_GAP, sender="analysis", payload={"host":"VM-01"}))
print(f"    réponse du Collect: has_gap={resp.payload['has_gap']}, {resp.detail}")

print(f"\n--- Journal du bus (traçabilité) ---")
for i in bus.interactions():
    print(f"    {i['from']} → {i['to']} [{i['type']}]: {i['detail']}")

print("\n" + "="*70)
print("VÉRIFICATIONS")
print("="*70)
vm01_vig = agent.vigilance_report().get("VM-01", {})
checks = [
    ("Falsification perçue → vigilance HEIGHTENED", vm01_vig.get("level")=="heightened"),
    ("k_sigma abaissé (surveillance resserrée)", vm01_vig.get("k_sigma",4.0) < 4.0),
    ("Gap perçu → re-collecte déclenchée", len(recollect_log) > 0),
    ("Re-collecte sur le bon host", any(h=="VM-01" for h,_ in recollect_log)),
    ("Répond aux requêtes CHECK_GAP", resp.payload["has_gap"]==True),
    ("Cœur du Collect inchangé (stats produites)", core.stats["processed"]==4),
    ("Échanges tracés sur le bus", len(bus.log) >= 2),
]
all_ok = True
for label, ok in checks:
    all_ok = all_ok and ok
    print(f"  [{'OK' if ok else 'ECHEC'}] {label}")
print(f"\n{'TOUS OK — le Collect est agentique' if all_ok else 'ÉCHECS'}")
