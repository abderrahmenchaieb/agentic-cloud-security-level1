# Decision Agent — frontière Niveau 1 / Niveau 2

Composant d'un système multi-agents pour la sécurité cloud (thèse « Agentic System for Cloud Security and Geolocation »).

Le Decision Agent est le **quatrième agent du Niveau 1**. Il corrèle les signaux des trois agents de détection, évalue la certitude, et **décide** : soit il propose directement des actions à l'utilisateur (attaque confirmée), soit il escalade vers le **Niveau 2** pour le calcul lourd (doute, ou anonymisation à percer).

---

## Architecture

```
signaux (Analysis + Anonymization + Collect)
     │
     ▼  [1] NORMALISATION → signaux communs
     ▼  [2] CORRÉLATION → entités (menace + anon par IP + intégrité par host)
     ▼  [3] ÉVALUATION DE CERTITUDE → décision (2 dimensions, règles)
     │
     ├─ CONFIRMÉ ─► [4] GÉNÉRATEUR D'ACTIONS (LLM+D3FEND) ─► actions à l'user
     │
     └─ ESCALADÉ ─► [5] ROUTEUR NIVEAU 2 ─► dossier (géoloc / investigation)

     (les deux coexistent : contenir ET localiser en parallèle)
```

**Niveau 2** (perspective, hors périmètre) : calcul approfondi (LLM lourd), et surtout **géolocalisation approximative** quand une anonymisation (VPN/Tor) masque l'origine d'un attaquant. Le Decision Agent ne fait pas ce calcul — il le déclenche et prépare le dossier.

---

## Le modèle décisionnel à deux dimensions

Validé par l'état de l'art SOC/SOAR (voir `decision_agent_justification_etat_art.md`).

**Dimension A — Certitude / action**
- Menace ≥ seuil_haut (signal fort seul) → **CONFIRMÉ**
- Menace ≥ seuil_moyen **+ falsification** → **CONFIRMÉ** (convergence)
- → si CONFIRMÉ : actions proposées à l'utilisateur

**Dimension B — Escalade Niveau 2 (indépendante)**
- Menace ≥ seuil_moyen **+ anonymisation** → escalade **géolocalisation**
- Menace ambiguë sans corroboration → escalade **investigation**
- Falsification/gap **seul** → surveillé (log), pas d'escalade

Les deux se cumulent : convergence maximale = **CONFIRMÉ + escalade géoloc**.

### L'asymétrie falsification vs anonymisation
- **Falsification** (Collect) = confirmateur de haute confiance de l'intention malveillante (« force multiplier ») — effacer des logs n'a pas d'explication légitime.
- **Anonymisation** (VPN/Tor) = signal contextuel ambigu (souvent légitime) — n'oriente que corrélé à une menace.

---

## L'IA : un seul module

Conformément au principe de tout le système (IA proportionnée à la tâche), **seul le générateur d'actions utilise l'IA** :
- un **LLM léger** (Qwen3/Phi-4 via Ollama, réutilisable de l'Analysis Agent) qui **formule et priorise** les actions ;
- ancré sur une base **D3FEND + ATT&CK Mitigations** (il choisit parmi des actions réelles, ne les invente pas) ;
- avec **anti-hallucination** (filtrage des actions hors base).

Le corrélateur, l'évaluateur et le routeur sont en **règles explicites** — auditable, défendable (les décisions ont des conséquences réelles).

### Raffinement « niveau artefacts » (différenciant)
Le générateur privilégie les défenses D3FEND qui opèrent sur les **artefacts réellement observés** (fournis par l'Analysis Agent via `observed_artifacts`), pas sur la technique abstraite. Exemple : si seul du trafic réseau a été vu, on propose les défenses réseau et on écarte les défenses fichier — recommandations ciblées sur ce qui s'est vraiment passé.

---

## Structure du package

```
decision_agent/
    __init__.py              API publique
    decision_schema.py       signaux normalisés + entité corrélée
    signal_normalizers.py    traduit les 3 sources vers le signal commun
    correlator.py            regroupe par entité (host/IP/fenêtre)
    certainty_evaluator.py   cœur décisionnel (2 dimensions, règles)
    defense_knowledge.py     base D3FEND + ATT&CK (technique→défenses)
    action_generator.py      générateur d'actions (le seul module IA)
    level2_router.py         prépare le dossier d'escalade Niveau 2
    decision_agent.py        orchestrateur (pipeline complet)
load_defenses.py             charger les vraies bases D3FEND + ATT&CK
example_minimal.py           exemple minimal
tests/                       tests de chaque brique
```

---

## Installation

```bash
pip install  # aucune dépendance lourde pour le cœur (règles + dataclasses)
# pour le générateur d'actions avec un vrai LLM :
pip install ollama
```

Le cœur (corrélation, évaluation, routage) ne dépend que de la bibliothèque standard.

---

## Utilisation rapide

```python
from decision_agent import DecisionAgent, ActionGenerator, DefenseKnowledgeBase

# avec le générateur d'actions (LLM) :
from ollama_llm import OllamaLLM   # réutilisé de l'Analysis Agent
agent = DecisionAgent(
    action_generator=ActionGenerator(OllamaLLM("qwen3:4b"), DefenseKnowledgeBase())
)

outputs = agent.decide(
    threat_verdicts=[...],      # ThreatVerdict de l'Analysis Agent
    anon_verdicts=[...],        # AnonymizationVerdict de l'Anonymization Agent
    gap_findings=[...],         # GapFinding du Collect Agent
    integrity_flags=[...],      # (host, detail) de falsification
)

for o in outputs.confirmed():
    print(o.action_plan.summary)          # actions à l'utilisateur
for d in outputs.level2_dossiers():
    print(d.mission, d.anonymized_ips)    # dossiers d'escalade Niveau 2
```

Sans LLM (`DecisionAgent()`) : l'agent décide et escalade, mais ne formule pas les actions en langage naturel.

---

## Brancher les vraies bases de défenses

```bash
# télécharger UNE FOIS (puis stocker en local) :
#   https://d3fend.mitre.org/api/ontology/inference/d3fend-full-mappings.json
python load_defenses.py d3fend-full-mappings.json attack_mitigations.json
```

**À adapter** : `load_d3fend_mappings()` et `load_attack_mitigations()` selon la structure exacte des fichiers (le mapping D3FEND relie technique ATT&CK → défense via l'artefact). Le mapping n'est pas exhaustif ni 1-à-1 → les mitigations ATT&CK servent de **filet** (couverture large).

---

## État et limites (honnête)

**Fonctionnel et testé** :
- ✅ Normalisation des 3 sources vers un signal commun.
- ✅ Corrélateur — convergence par host/IP, gestion des orphelins.
- ✅ Évaluateur de certitude — table de décision complète, 2 dimensions.
- ✅ Générateur d'actions — raffinement artefacts + anti-hallucination.
- ✅ Routeur Niveau 2 — dossiers géoloc/investigation.
- ✅ Assemblage — double flux (actions + dossiers), coexistence confirmé/escaladé.

**À confirmer sur données réelles / intégration** :
- ⚠️ Les seuils (threat_high/medium/low) sont à calibrer sur des incidents réels.
- ⚠️ La base D3FEND réelle à charger (échantillon d'exemple ici).
- ⚠️ Qualité de formulation du vrai LLM (testé avec un LLM simulé).
- ⚠️ Intégration : recevoir les vraies sorties des 3 agents (les structures sont compatibles).

**Perspective (hors périmètre)** :
- 🔲 Le Niveau 2 lui-même (calcul lourd, géolocalisation approximative).

---

## Prochaines étapes

1. Télécharger et brancher les vraies bases D3FEND + ATT&CK.
2. Calibrer les seuils sur des incidents réels.
3. Brancher le vrai LLM (réutiliser l'instance de l'Analysis Agent).
4. Intégrer les sorties réelles des trois agents.
5. (Perspective) concevoir le Niveau 2.
