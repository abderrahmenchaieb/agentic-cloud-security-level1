"""Test du routeur Niveau 2 : préparation des dossiers d'escalade."""
from decision_agent.decision_schema import (NormalizedSignal, SignalSource, SignalKind, CorrelatedEntity)
from decision_agent.certainty_evaluator import CertaintyEvaluator
from decision_agent.level2_router import Level2Router

def threat_sig(host, score, ips=None):
    return NormalizedSignal(SignalSource.ANALYSIS, SignalKind.THREAT, host=host, ips=ips or [],
        severity=score, detail="PowerShell C2 puis reconnaissance",
        payload={"observed_artifacts":["process","network_traffic"],
                 "techniques":[{"id":"T1059.001"},{"id":"T1071.001"}]})
def anon_sig(ip, label, conf):
    return NormalizedSignal(SignalSource.ANONYMIZATION, SignalKind.ANONYMIZATION, ips=[ip], severity=conf, detail=label)
def integ_sig(host, sev=0.8):
    return NormalizedSignal(SignalSource.COLLECT, SignalKind.INTEGRITY, host=host, severity=sev,
                            detail="[R1_timestomping] logs falsifiés")
def entity(host, threat=None, anons=None, integs=None):
    return CorrelatedEntity(entity_key=f"ent-{host}", host=host, threat_signal=threat,
                            anonymization_signals=anons or [], integrity_signals=integs or [])

ev = CertaintyEvaluator()
router = Level2Router()

print("="*72)
print("1. ESCALADE GÉOLOCALISATION (menace forte + anonymisation Tor)")
print("="*72)
e1 = entity("VM-01", threat=threat_sig("VM-01", 0.88, ["185.220.101.47"]),
            anons=[anon_sig("185.220.101.47","tor",0.98)])
d1 = ev.evaluate(e1)
dossier1 = router.route(e1, d1)
print(f"Décision: {d1.certainty.value}, escalade={d1.escalate} ({d1.mission.value})")
print(f"\nDossier Niveau 2:")
import json
print(json.dumps(dossier1.to_dict(), indent=2, ensure_ascii=False))

print("\n" + "="*72)
print("2. ESCALADE INVESTIGATION (menace ambiguë seule)")
print("="*72)
e2 = entity("VM-05", threat=threat_sig("VM-05", 0.45))
d2 = ev.evaluate(e2)
dossier2 = router.route(e2, d2)
print(f"Décision: {d2.certainty.value}, escalade={d2.escalate} ({d2.mission.value})")
print(f"Mission: {dossier2.mission}")
print(f"Calculs demandés: {dossier2.requested_computations}")
print(f"IPs à géolocaliser: {dossier2.anonymized_ips} (vide = normal, pas d'anon)")

print("\n" + "="*72)
print("3. CONVERGENCE MAXIMALE (confirmé + escalade géoloc + contexte falsif)")
print("="*72)
e3 = entity("VM-09", threat=threat_sig("VM-09", 0.90, ["185.220.101.47"]),
            anons=[anon_sig("185.220.101.47","tor",0.98)], integs=[integ_sig("VM-09")])
d3 = ev.evaluate(e3)
dossier3 = router.route(e3, d3)
print(f"Décision: {d3.certainty.value} (needs_actions={d3.needs_actions}), escalade={d3.escalate} ({d3.mission.value})")
print(f"→ Le cas est CONFIRMÉ (actions en parallèle) ET escaladé pour géoloc")
print(f"\nDossier: mission={dossier3.mission}")
print(f"   IPs anonymisées à percer: {dossier3.anonymized_ips} ({dossier3.anonymization_types})")
print(f"   Contexte falsification: {dossier3.integrity_context}")
print(f"   Calculs demandés: {dossier3.requested_computations}")

print("\n" + "="*72)
print("4. PAS D'ESCALADE (cas normal / confirmé simple sans anon)")
print("="*72)
e4 = entity("VM-10", threat=threat_sig("VM-10", 0.92))  # forte, seule → confirmé mais pas escaladé
d4 = ev.evaluate(e4)
dossier4 = router.route(e4, d4)
print(f"Décision: {d4.certainty.value}, escalade={d4.escalate}")
print(f"Dossier: {dossier4} (doit être None — rien à escalader)")

print("\n" + "="*72)
print("VÉRIFICATIONS")
print("="*72)
checks = [
    ("Géoloc: IP anonymisée transmise", "185.220.101.47" in dossier1.anonymized_ips),
    ("Géoloc: type Tor transmis", "tor" in dossier1.anonymization_types),
    ("Géoloc: calcul de géolocalisation demandé",
     "approximate_geolocation_behind_anonymization" in dossier1.requested_computations),
    ("Investigation: pas d'IP à géolocaliser", dossier2.anonymized_ips == []),
    ("Investigation: LLM lourd demandé", "deep_llm_analysis" in dossier2.requested_computations),
    ("Convergence max: contexte falsification transmis", len(dossier3.integrity_context) > 0),
    ("Convergence max: confirmé ET escaladé", d3.needs_actions and d3.escalate),
    ("Pas d'escalade → pas de dossier", dossier4 is None),
]
all_ok = True
for label, ok in checks:
    all_ok = all_ok and ok
    print(f"   [{'OK' if ok else 'ECHEC'}] {label}")
print(f"\n{'TOUS OK' if all_ok else 'ÉCHECS'}")
