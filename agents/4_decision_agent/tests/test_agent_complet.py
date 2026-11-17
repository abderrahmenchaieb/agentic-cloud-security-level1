"""Test du Decision Agent complet de bout en bout."""
from dataclasses import dataclass, field
from decision_agent import DecisionAgent
from decision_agent.action_generator import ActionGenerator
from decision_agent.defense_knowledge import DefenseKnowledgeBase

# --- Imiter les sorties BRUTES des trois agents ---
@dataclass
class ThreatVerdict:
    host: str; is_attack: bool; attack_score: float
    hypothesis: str = ""; techniques: list = field(default_factory=list)
    sequence_summary: dict = field(default_factory=dict)
    observed_artifacts: list = field(default_factory=list)
@dataclass
class AnonVerdict:
    flow_id: str; external_ip: str; label: str; confidence: float
@dataclass
class Gap:
    gap_type: str; source_key: str; detail: str; severity_score: float; detected_at=None

# --- LLM simulé pour le générateur d'actions ---
class MockLLM:
    def generate(self, prompt):
        return '''```json
{"summary": "Attaque PowerShell/C2 confirmée. Contenir la connexion sortante et le processus.",
 "actions": [
   {"action_id":"D3-OTF","priority":"immediate","reason":"Bloquer le C2 sortant observé"},
   {"action_id":"D3-NTA","priority":"high","reason":"Analyser le trafic réseau"},
   {"action_id":"D3-PSEP","priority":"high","reason":"Analyser le processus suspect"}
 ]}
```'''

agent = DecisionAgent(action_generator=ActionGenerator(MockLLM(), DefenseKnowledgeBase()))

# --- Scénario réaliste : sorties des 3 agents sur un cycle ---
threats = [
    # attaque CONFIRMÉE + anonymisation → confirmé + escalade géoloc
    ThreatVerdict(host="VM-01", is_attack=True, attack_score=0.90,
                  hypothesis="PowerShell encodé vers C2 Tor puis reconnaissance",
                  techniques=[{"id":"T1059.001"},{"id":"T1071.001"},{"id":"T1033"}],
                  sequence_summary={"external_ips":["185.220.101.47"]},
                  observed_artifacts=["process","network_traffic"]),
    # menace ambiguë seule → doute → investigation
    ThreatVerdict(host="VM-05", is_attack=True, attack_score=0.45,
                  hypothesis="Activité suspecte non concluante",
                  techniques=[{"id":"T1059.001"}],
                  sequence_summary={"external_ips":[]},
                  observed_artifacts=["process"]),
    # séquence NORMALE → ignorée
    ThreatVerdict(host="VM-06", is_attack=False, attack_score=0.1),
]
anons = [
    AnonVerdict("F1","185.220.101.47","tor",0.98),   # lié à la menace VM-01 par IP
    AnonVerdict("F2","8.8.8.8","normal",0.2),          # normal → ignoré
    AnonVerdict("F3","45.83.220.10","vpn",0.71),       # orphelin (pas de menace) → ignoré
]
gaps = [
    Gap("silence_gap","VM-01:sysmon","source silencieuse 90s",0.75),  # même host que l'attaque
]

outputs = agent.decide(threat_verdicts=threats, anon_verdicts=anons, gap_findings=gaps)

print("="*74)
print("DECISION AGENT — pipeline complet")
print("="*74)
print(f"\nStats: {outputs.stats}\n")

for o in outputs.outcomes:
    d = o.decision
    print(f"── Entité {d.entity_key} (host {d.host}) ──")
    print(f"   Certitude: {d.certainty.value.upper()}  |  Escalade: {d.escalate}"
          + (f" → {d.mission.value}" if d.escalate else ""))
    print(f"   Règles: {d.triggered_rules}")
    if o.action_plan:
        print(f"   ACTIONS proposées à l'utilisateur:")
        print(f"      « {o.action_plan.summary} »")
        for a in o.action_plan.actions:
            print(f"      [{a.priority}] {a.action_id} — {a.name}")
    if o.level2_dossier:
        dos = o.level2_dossier
        print(f"   DOSSIER Niveau 2: mission={dos.mission}")
        if dos.anonymized_ips:
            print(f"      IPs à géolocaliser: {dos.anonymized_ips} ({dos.anonymization_types})")
        print(f"      calculs: {dos.requested_computations}")
    print()

print("="*74)
print("VÉRIFICATIONS")
print("="*74)
# retrouver les entités
conf = next((o for o in outputs.outcomes if o.decision.host=="VM-01"), None)
doubt = next((o for o in outputs.outcomes if o.decision.host=="VM-05"), None)
checks = [
    ("VM-01: attaque confirmée", conf and conf.decision.certainty.value=="confirmed"),
    ("VM-01: actions générées (contenir)", conf and conf.action_plan and len(conf.action_plan.actions)>0),
    ("VM-01: escaladée pour géoloc EN PARALLÈLE", conf and conf.decision.escalate and conf.level2_dossier),
    ("VM-01: IP Tor transmise au Niveau 2", conf and "185.220.101.47" in conf.level2_dossier.anonymized_ips),
    ("VM-01: contexte falsification (gap) présent", conf and len(conf.level2_dossier.integrity_context)>0),
    ("VM-05: menace ambiguë → investigation", doubt and doubt.decision.mission.value=="investigation"),
    ("VM-05: pas d'actions (pas confirmé)", doubt and doubt.action_plan is None),
    ("Séquence normale VM-06 ignorée", not any(o.decision.host=="VM-06" for o in outputs.outcomes)),
    ("VPN orphelin ignoré", not any("45.83.220.10" in (o.level2_dossier.anonymized_ips if o.level2_dossier else []) for o in outputs.outcomes)),
]
all_ok = True
for label, ok in checks:
    all_ok = all_ok and ok
    print(f"   [{'OK' if ok else 'ECHEC'}] {label}")
print(f"\n{'='*74}")
print(f"{'TOUS LES CAS OK' if all_ok else 'DES ÉCHECS'}")
print("="*74)
