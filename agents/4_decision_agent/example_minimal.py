#!/usr/bin/env python3
"""Exemple minimal : le Decision Agent sur un cas de convergence."""
from dataclasses import dataclass, field
from decision_agent import DecisionAgent, ActionGenerator, DefenseKnowledgeBase

# structures imitant les sorties des 3 agents
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

# LLM simulé (remplace par OllamaLLM en production)
class DemoLLM:
    def generate(self, prompt):
        return '{"summary":"Attaque C2 confirmée, contenir la connexion et le processus.","actions":[{"action_id":"D3-OTF","priority":"immediate","reason":"Bloquer le C2 observé"},{"action_id":"D3-PSEP","priority":"high","reason":"Analyser le processus"}]}'

agent = DecisionAgent(action_generator=ActionGenerator(DemoLLM(), DefenseKnowledgeBase()))

# cas de convergence : attaque forte + Tor + gap de logs, même host
outputs = agent.decide(
    threat_verdicts=[ThreatVerdict(host="VM-01", is_attack=True, attack_score=0.90,
        hypothesis="PowerShell encodé vers C2 Tor puis reconnaissance",
        techniques=[{"id":"T1059.001"},{"id":"T1071.001"}],
        sequence_summary={"external_ips":["185.220.101.47"]},
        observed_artifacts=["process","network_traffic"])],
    anon_verdicts=[AnonVerdict("F1","185.220.101.47","tor",0.98)],
    gap_findings=[Gap("silence_gap","VM-01:sysmon","source silencieuse 90s",0.75)],
)

print("Stats:", outputs.stats)
for o in outputs.outcomes:
    d = o.decision
    print(f"\nHost {d.host}: {d.certainty.value.upper()} | escalade={d.escalate}"
          + (f" ({d.mission.value})" if d.escalate else ""))
    print(f"  rationale: {d.rationale}")
    if o.action_plan:
        print(f"  ACTIONS: {o.action_plan.summary}")
        for a in o.action_plan.actions:
            print(f"    [{a.priority}] {a.action_id} — {a.name}")
    if o.level2_dossier:
        print(f"  NIVEAU 2: {o.level2_dossier.mission}, IPs={o.level2_dossier.anonymized_ips}")
