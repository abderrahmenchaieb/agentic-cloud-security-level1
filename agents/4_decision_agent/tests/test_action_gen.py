"""Test du générateur d'actions : raffinement artefacts + anti-hallucination."""
from decision_agent.defense_knowledge import DefenseKnowledgeBase
from decision_agent.action_generator import ActionGenerator, parse_action_response

kb = DefenseKnowledgeBase()

# --- 1. Le raffinement par artefacts (SANS LLM, test direct de la base) ---
print("="*70)
print("1. RAFFINEMENT PAR ARTEFACTS (base de connaissances)")
print("="*70)
techniques = ["T1059.001", "T1071.001", "T1036.005"]

# cas A : on a observé réseau + process (mais PAS de fichier)
cand_A = kb.candidate_actions(techniques, observed_artifacts=["network_traffic","process"])
print(f"\nArtefacts observés = [network_traffic, process]")
print(f"Actions D3FEND candidates ({len([a for a in cand_A if a.source=='d3fend'])} défenses):")
for a in cand_A:
    if a.source == "d3fend":
        print(f"   {a.action_id} ({a.name}) [opère sur {a.artifact}]")
# vérifier : pas de défense fichier (D3-FCA opère sur d3f:File, non observé)
has_file_defense = any(a.artifact=="d3f:File" for a in cand_A if a.source=="d3fend")
print(f"   → défense FICHIER (D3-FCA) écartée car pas de fichier observé : {'OK' if not has_file_defense else 'ECHEC'}")

# cas B : on a AUSSI observé un fichier → la défense fichier réapparaît
cand_B = kb.candidate_actions(techniques, observed_artifacts=["network_traffic","process","file"])
has_file_defense_B = any(a.artifact=="d3f:File" for a in cand_B if a.source=="d3fend")
print(f"\nArtefacts observés = [network_traffic, process, FILE]")
print(f"   → défense FICHIER (D3-FCA) réapparaît : {'OK' if has_file_defense_B else 'ECHEC'}")

# cas C : sans info d'artefacts → toutes les défenses (pas de raffinement)
cand_C = kb.candidate_actions(techniques, observed_artifacts=None)
print(f"\nSans info d'artefacts → toutes les défenses ({len(cand_C)} actions, pas de filtrage)")

# --- 2. Le LLM formule + anti-hallucination ---
print("\n" + "="*70)
print("2. GÉNÉRATION D'ACTIONS (LLM simulé) + ANTI-HALLUCINATION")
print("="*70)

class MockLLM:
    def __init__(self, mode="good"): self.mode = mode
    def generate(self, prompt):
        if self.mode == "good":
            return '''```json
{"summary": "PowerShell encodé a contacté un C2 externe puis fait de la reconnaissance. Contenir la connexion et le processus.",
 "actions": [
   {"action_id": "D3-OTF", "priority": "immediate", "reason": "Bloquer le trafic C2 sortant observé"},
   {"action_id": "D3-NTA", "priority": "high", "reason": "Analyser le trafic réseau"},
   {"action_id": "D3-PSEP", "priority": "high", "reason": "Analyser le processus PowerShell suspect"},
   {"action_id": "M1038", "priority": "medium", "reason": "Prévenir l'exécution non autorisée"}
 ]}
```'''
        else:  # hallucinate : invente D3-FAKE et M9999
            return '''{"summary": "test",
 "actions": [
   {"action_id": "D3-OTF", "priority": "immediate", "reason": "valide"},
   {"action_id": "D3-FAKE", "priority": "high", "reason": "INVENTÉ"},
   {"action_id": "M9999", "priority": "high", "reason": "INVENTÉ"}
 ]}'''

gen = ActionGenerator(MockLLM("good"), kb)
plan = gen.generate("ent-1", "VM-01",
                    "PowerShell encodé vers C2 puis reconnaissance",
                    techniques, observed_artifacts=["network_traffic","process"])
print(f"\nRésumé: {plan.summary}")
print("Actions recommandées:")
for a in plan.actions:
    print(f"   [{a.priority:9}] {a.action_id} ({a.name}) — {a.reason}")

# anti-hallucination
print("\n--- Test anti-hallucination ---")
gen_h = ActionGenerator(MockLLM("hallucinate"), kb)
plan_h = gen_h.generate("ent-2", "VM-01", "test", techniques,
                        observed_artifacts=["network_traffic","process"])
kept = {a.action_id for a in plan_h.actions}
print(f"LLM a produit: D3-OTF (valide), D3-FAKE (inventé), M9999 (inventé)")
print(f"Actions gardées: {kept}")
print(f"   D3-FAKE filtré : {'OK' if 'D3-FAKE' not in kept else 'ECHEC'}")
print(f"   M9999 filtré   : {'OK' if 'M9999' not in kept else 'ECHEC'}")
print(f"   D3-OTF gardé   : {'OK' if 'D3-OTF' in kept else 'ECHEC'}")

print("\n" + "="*70)
print("VÉRIFICATIONS GLOBALES")
print("="*70)
checks = [
    ("Raffinement: défense fichier écartée si pas d'artefact fichier", not has_file_defense),
    ("Raffinement: défense fichier présente si fichier observé", has_file_defense_B),
    ("Sans artefacts: toutes les défenses", len(cand_C) > len([a for a in cand_A if a.source=='d3fend'])),
    ("LLM formule un plan cohérent", len(plan.actions) >= 3),
    ("Anti-hallucination: actions inventées filtrées", "D3-FAKE" not in kept and "M9999" not in kept),
    ("Action valide conservée", "D3-OTF" in kept),
]
all_ok = True
for label, ok in checks:
    all_ok = all_ok and ok
    print(f"   [{'OK' if ok else 'ECHEC'}] {label}")
print(f"\n{'TOUS OK' if all_ok else 'ÉCHECS'}")
