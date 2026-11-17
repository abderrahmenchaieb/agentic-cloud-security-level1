"""Test du contrat d'entrée : normalisation des 3 sources vers signal commun."""
from dataclasses import dataclass, field
from decision_agent.decision_schema import NormalizedSignal, SignalSource, SignalKind
from decision_agent.signal_normalizers import (normalize_threat, normalize_anonymization,
    normalize_gap, normalize_all)

# --- Imiter les vraies structures des agents ---
@dataclass
class FakeThreatVerdict:  # ThreatVerdict de l'Analysis Agent
    host: str; is_attack: bool; attack_score: float
    hypothesis: str = ""
    techniques: list = field(default_factory=list)
    sequence_summary: dict = field(default_factory=dict)
    observed_artifacts: list = field(default_factory=list)

@dataclass
class FakeAnonVerdict:  # AnonymizationVerdict
    flow_id: str; external_ip: str; label: str; confidence: float; method: str = "gnn"

@dataclass
class FakeGap:  # GapFinding du Collect Agent
    gap_type: str; source_key: str; detail: str; severity_score: float; detected_at=None

print("="*64)
print("1. NORMALISATION D'UNE MENACE (Analysis)")
print("="*64)
threat = FakeThreatVerdict(
    host="VM-01", is_attack=True, attack_score=0.87,
    hypothesis="PowerShell encodé vers C2 puis reconnaissance",
    techniques=[{"id":"T1059.001","name":"PowerShell"}],
    sequence_summary={"external_ips":["185.220.101.47"]},
    observed_artifacts=["process","network_traffic"],
)
s = normalize_threat(threat)
print(f"  source={s.source.value} kind={s.kind.value}")
print(f"  host={s.host} ips={s.ips} severity={s.severity}")
print(f"  artefacts (via payload)={s.payload.observed_artifacts}")

# une séquence NORMALE ne doit pas produire de signal
normal = FakeThreatVerdict(host="VM-01", is_attack=False, attack_score=0.1)
print(f"  séquence normale → signal = {normalize_threat(normal)} (doit être None)")

print("\n" + "="*64)
print("2. NORMALISATION D'UNE ANONYMISATION (Anonymization)")
print("="*64)
for lbl, conf in [("tor",0.98),("vpn",0.71),("normal",0.3)]:
    av = FakeAnonVerdict(flow_id="F1", external_ip="185.220.101.47", label=lbl, confidence=conf)
    s = normalize_anonymization(av)
    if s:
        print(f"  {lbl}: source={s.source.value} ip={s.ips} severity={s.severity} detail={s.detail}")
    else:
        print(f"  {lbl}: pas de signal (normal/unknown ignoré) ✓")

print("\n" + "="*64)
print("3. NORMALISATION D'UN GAP (Collect)")
print("="*64)
gap = FakeGap(gap_type="silence_gap", source_key="VM-01:sysmon",
              detail="source silencieuse depuis 90s", severity_score=0.75)
s = normalize_gap(gap)
print(f"  source={s.source.value} kind={s.kind.value} host={s.host} severity={s.severity}")
print(f"  detail={s.detail}")

print("\n" + "="*64)
print("4. NORMALISATION EN LOT")
print("="*64)
signals = normalize_all(
    threat_verdicts=[threat, normal],
    anon_verdicts=[FakeAnonVerdict("F1","185.220.101.47","tor",0.98),
                   FakeAnonVerdict("F2","8.8.8.8","normal",0.2)],
    gap_findings=[gap],
    integrity_flags=[("VM-01","[R1_timestomping] event_time 1970")],
)
print(f"  {len(signals)} signaux normalisés (attendu: 3 = 1 menace + 1 tor + 1 gap + 1 falsif = 4)")
from collections import Counter
by_kind = Counter(s.kind.value for s in signals)
print(f"  par type: {dict(by_kind)}")

print("\n" + "="*64)
print("VÉRIFICATIONS")
print("="*64)
checks = [
    ("Menace normalisée avec host+ip", normalize_threat(threat).host=="VM-01"),
    ("Séquence normale ignorée", normalize_threat(normal) is None),
    ("Tor normalisé", normalize_anonymization(FakeAnonVerdict("F","1.2.3.4","tor",0.9)) is not None),
    ("Normal (anon) ignoré", normalize_anonymization(FakeAnonVerdict("F","1.2.3.4","normal",0.3)) is None),
    ("Gap: host extrait de source_key", normalize_gap(gap).host=="VM-01"),
    ("Lot: 4 signaux (menace+tor+gap+falsif)", len(signals)==4),
    ("Artefacts préservés dans le payload", normalize_threat(threat).payload.observed_artifacts==["process","network_traffic"]),
]
for label, ok in checks:
    print(f"  [{'OK' if ok else 'ECHEC'}] {label}")
