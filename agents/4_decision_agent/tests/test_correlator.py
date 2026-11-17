"""Test du corrélateur sur des scénarios de convergence."""
from decision_agent.decision_schema import NormalizedSignal, SignalSource, SignalKind
from decision_agent.correlator import Correlator, CorrelatorConfig

def threat(host, score, ips, hyp=""):
    return NormalizedSignal(SignalSource.ANALYSIS, SignalKind.THREAT, host=host,
                            ips=ips, severity=score, detail=hyp,
                            payload={"observed_artifacts":["process","network_traffic"],
                                     "techniques":[{"id":"T1059.001"}]})
def anon(ip, label, conf):
    return NormalizedSignal(SignalSource.ANONYMIZATION, SignalKind.ANONYMIZATION,
                            ips=[ip], severity=conf, detail=label)
def integrity(host, detail, sev=0.8):
    return NormalizedSignal(SignalSource.COLLECT, SignalKind.INTEGRITY, host=host,
                            severity=sev, detail=detail)

# --- Scénario : 4 situations mélangées ---
signals = [
    # A. CONVERGENCE : menace + Tor (même IP) + falsification (même host) → le cas fort
    threat("VM-01", 0.87, ["185.220.101.47"], "PowerShell C2 + recon"),
    anon("185.220.101.47", "tor", 0.98),
    integrity("VM-01", "[R1_timestomping] logs falsifiés"),

    # B. menace SEULE (pas d'anon, pas d'intégrité)
    threat("VM-05", 0.92, ["203.0.113.9"], "Mouvement latéral"),

    # C. anonymisation ORPHELINE (VPN sans menace) → doit être IGNORÉE
    anon("45.83.220.10", "vpn", 0.71),

    # D. falsification ORPHELINE (sans menace) → doit être GARDÉE (signal faible réel)
    integrity("VM-09", "[gap] source silencieuse 90s", 0.75),
]

correlator = Correlator()
entities = correlator.correlate(signals)

print(f"{len(signals)} signaux → {len(entities)} entités corrélées\n")
for i, e in enumerate(entities):
    print(f"Entité {i+1}: {e.summary()}")
    if e.has_threat():
        print(f"   MENACE score={e.threat_score():.2f}")
    if e.has_anonymization():
        print(f"   ANONYMISATION: {e.anonymization_labels()} (score {e.max_anonymization_score():.2f})")
    if e.has_integrity_issue():
        print(f"   INTÉGRITÉ: {[s.detail for s in e.integrity_signals]}")
    print()

print("="*64)
print("VÉRIFICATIONS")
print("="*64)
# retrouver l'entité convergente (VM-01)
conv = next((e for e in entities if e.host=="VM-01" and e.has_threat()), None)
seule = next((e for e in entities if e.host=="VM-05"), None)
orph_int = next((e for e in entities if e.host=="VM-09"), None)
anon_orph = any("45.83.220.10" in s.ips for e in entities for s in e.anonymization_signals)

checks = [
    ("Convergence VM-01: menace+tor+falsif dans UNE entité",
     conv and conv.has_threat() and conv.has_anonymization() and conv.has_integrity_issue()),
    ("Tor bien rattaché par IP (185.220.101.47)",
     conv and "tor" in conv.anonymization_labels()),
    ("Falsification bien rattachée par host (VM-01)",
     conv and conv.has_integrity_issue()),
    ("Menace seule VM-05: pas d'anon ni intégrité",
     seule and seule.has_threat() and not seule.has_anonymization() and not seule.has_integrity_issue()),
    ("Anonymisation orpheline (VPN seul) IGNORÉE",
     not anon_orph),
    ("Falsification orpheline VM-09 GARDÉE (sans menace)",
     orph_int and not orph_int.has_threat() and orph_int.has_integrity_issue()),
    ("Artefacts accessibles depuis l'entité convergente",
     conv and conv.observed_artifacts()==["process","network_traffic"]),
]
for label, ok in checks:
    print(f"  [{'OK' if ok else 'ECHEC'}] {label}")
