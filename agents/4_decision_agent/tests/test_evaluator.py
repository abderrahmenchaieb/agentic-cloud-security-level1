"""Test de l'évaluateur de certitude sur toute la table de décision."""
from decision_agent.decision_schema import (NormalizedSignal, SignalSource, SignalKind, CorrelatedEntity)
from decision_agent.certainty_evaluator import CertaintyEvaluator, CertaintyLevel, EscalationMission

def threat_sig(host, score, ips=None):
    return NormalizedSignal(SignalSource.ANALYSIS, SignalKind.THREAT, host=host,
                            ips=ips or [], severity=score,
                            payload={"observed_artifacts":["process","network_traffic"],
                                     "techniques":[{"id":"T1059.001"}]})
def anon_sig(ip, label, conf):
    return NormalizedSignal(SignalSource.ANONYMIZATION, SignalKind.ANONYMIZATION,
                            ips=[ip], severity=conf, detail=label)
def integ_sig(host, sev=0.8):
    return NormalizedSignal(SignalSource.COLLECT, SignalKind.INTEGRITY, host=host,
                            severity=sev, detail="[R1_timestomping] falsif")

def entity(host, threat=None, anons=None, integs=None):
    return CorrelatedEntity(entity_key=f"ent-{host}", host=host, threat_signal=threat,
                            anonymization_signals=anons or [], integrity_signals=integs or [])

ev = CertaintyEvaluator()

# --- La table de décision complète ---
cases = [
    ("Menace TRÈS FORTE seule (0.90)",
     entity("H1", threat=threat_sig("H1", 0.90)),
     CertaintyLevel.CONFIRMED, False),

    ("Menace moyenne (0.65) + FALSIFICATION",
     entity("H2", threat=threat_sig("H2", 0.65), integs=[integ_sig("H2")]),
     CertaintyLevel.CONFIRMED, False),

    ("Menace forte (0.88) + ANONYMISATION (convergence max)",
     entity("H3", threat=threat_sig("H3", 0.88, ["1.2.3.4"]), anons=[anon_sig("1.2.3.4","tor",0.98)]),
     CertaintyLevel.CONFIRMED, True),

    ("Menace forte + falsif + anon (CONVERGENCE MAXIMALE)",
     entity("H4", threat=threat_sig("H4", 0.88, ["1.2.3.4"]),
            anons=[anon_sig("1.2.3.4","tor",0.98)], integs=[integ_sig("H4")]),
     CertaintyLevel.CONFIRMED, True),

    ("Menace moyenne (0.65) + ANONYMISATION (pas de falsif)",
     entity("H5", threat=threat_sig("H5", 0.65, ["1.2.3.4"]), anons=[anon_sig("1.2.3.4","vpn",0.75)]),
     CertaintyLevel.DOUBTFUL, True),

    ("Menace AMBIGUË (0.45) seule",
     entity("H6", threat=threat_sig("H6", 0.45)),
     CertaintyLevel.DOUBTFUL, True),

    ("FALSIFICATION seule (pas de menace)",
     entity("H7", integs=[integ_sig("H7")]),
     CertaintyLevel.MONITORED, False),

    ("Rien de significatif (pas de menace)",
     entity("H8"),
     CertaintyLevel.NORMAL, False),
]

print("="*78)
print("TABLE DE DÉCISION — évaluateur de certitude (2 dimensions)")
print("="*78)
all_ok = True
for nom, ent, exp_certainty, exp_escalate in cases:
    d = ev.evaluate(ent)
    ok = (d.certainty == exp_certainty and d.escalate == exp_escalate)
    all_ok = all_ok and ok
    tag = "OK" if ok else "ECHEC"
    print(f"\n[{tag}] {nom}")
    print(f"      → certitude={d.certainty.value.upper()} | escalade={d.escalate}"
          + (f" ({d.mission.value})" if d.escalate else ""))
    print(f"      règles: {d.triggered_rules}")
    if not ok:
        print(f"      ATTENDU: certitude={exp_certainty.value}, escalade={exp_escalate}")

print("\n" + "="*78)
print("VÉRIFICATION DES CAS CLÉS")
print("="*78)
# convergence maximale : confirmé ET escaladé géoloc
conv = ev.evaluate(cases[3][1])
print(f"[{'OK' if conv.needs_actions and conv.escalate and conv.mission==EscalationMission.GEOLOCATION else 'ECHEC'}] "
      f"Convergence max = ACTIONS (contenir) + ESCALADE géoloc (localiser) en parallèle")
print(f"     needs_actions={conv.needs_actions}, escalate={conv.escalate}, mission={conv.mission.value}")

# falsification traitée comme confirmateur (asymétrie)
falsif = ev.evaluate(cases[1][1])   # menace 0.65 + falsif → CONFIRMÉ
anon = ev.evaluate(cases[4][1])     # menace 0.65 + anon → DOUTEUX seulement
print(f"\n[{'OK' if falsif.certainty==CertaintyLevel.CONFIRMED and anon.certainty==CertaintyLevel.DOUBTFUL else 'ECHEC'}] "
      f"ASYMÉTRIE : même menace (0.65), falsif→CONFIRMÉ mais anon→DOUTEUX")
print(f"     falsif: {falsif.certainty.value} | anon: {anon.certainty.value}")

print(f"\n{'='*78}")
print(f"RÉSULTAT GLOBAL : {'TOUS LES CAS OK' if all_ok else 'DES ÉCHECS À CORRIGER'}")
print("="*78)
