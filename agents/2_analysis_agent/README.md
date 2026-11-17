# Analysis Agent — détecteur de menaces par corrélation de séquences

Composant d'un système multi-agents pour la sécurité cloud (thèse « Agentic System for Cloud Security and Geolocation »).

Sur des données saines (fournies par le Collect Agent), l'Analysis Agent détecte les **attaques** par corrélation de séquences multi-étapes, et attribue les techniques **MITRE ATT&CK**.

---

## Architecture — Option C

```
events (du Collect Agent)
   │
   ▼  [1] SEQUENCE BUILDER (mécanique) → séquences
   │        via ProcessGUID + fenêtre temporelle
   ▼  [2] ÉTAGE 1 — ML de détection (attaque/normal) sur TOUTES les séquences
   │        rapide, orienté RAPPEL
   │        └── normal → écarté
   ▼  [3] ÉTAGE 2 — LLM + RAG MITRE (SEULEMENT sur le suspect)
   │        hypothèse d'attaque + techniques MITRE
   ▼
   verdicts → Decision Agent
```

**Le ML filtre** (rapide, sur tout) ; **le LLM interprète** (coûteux, sur le suspect). Chaque outil à sa tâche naturelle.

---

## Tâche facile vs tâche dure

| Sous-tâche | Difficulté | Approche |
|---|---|---|
| **Détection** (« est-ce une attaque ? ») | Facile (~90-97%) | ML (Étage 1) |
| **Attribution MITRE** (« quelle technique ? ») | **Dure** (~42% top-1) | LLM + RAG (Étage 2) |

**Règles d'or** : viser le **top-k** pour MITRE, pas le top-1. Mesurer détection et MITRE **séparément**.

---

## Anti-hallucination (double barrière)

Le problème MITRE est atténué par deux garde-fous :
1. **RAG** : le LLM ne voit que des techniques candidates RÉELLES (récupérées par similarité) → il choisit, il n'invente pas.
2. **Parsing** : toute technique hors de la liste candidate est FILTRÉE côté code.

→ Même si le LLM hallucine un ID, il ne passe jamais dans le verdict final.

---

## Structure du package

```
analysis_agent/
    __init__.py                API publique
    sequence_schema.py         Event, Sequence (contrat d'entrée)
    sequence_builder.py        regroupement mécanique (ProcessGUID)
    sequence_features.py       features de séquence pour l'Étage 1
    sequence_detector.py       Étage 1 : ML de détection (orienté rappel)
    mitre_rag.py               RAG MITRE (embedding flexible)
    mitre_sample.py            échantillon (→ remplacer par mitre_matrix.json)
    interpretation_engine.py   Étage 2 : LLM + anti-hallucination
    analysis_agent.py          orchestrateur (Option C)
ollama_llm.py                  brancher un vrai LLM (Qwen3/Phi-4 via Ollama)
run_with_windows_apt.py        point d'entrée avec de vraies données
example_minimal.py             exemple minimal
tests/                         tests de chaque brique
```

---


### Sortie enrichie pour le Decision Agent

Chaque `ThreatVerdict` expose `observed_artifacts` : les artefacts numériques
**réellement observés** dans la séquence (`network_traffic`, `file`,
`registry_key`, `process`, `process_access`, `module_load`, `authentication`),
dérivés des catégories d'événements.

Ces étiquettes sont **neutres** (pas des IDs D3FEND) : le mapping vers
l'ontologie D3FEND vit dans le **Decision Agent**, qui porte la connaissance
défensive. Cela permet au Decision Agent de proposer les contre-mesures qui
opèrent sur ce qui s'est **vraiment passé** (raffinement « niveau artefacts »),
plutôt que sur la technique abstraite — sans créer de liaison directe
Collect → Decision (l'info transite par l'Analysis Agent qui a déjà corrélé
la séquence).

---

## Installation

```bash
pip install scikit-learn numpy
# pour le vrai LLM :
pip install ollama          # + installer Ollama et tirer un modèle
```

---

## Utilisation rapide

```python
from analysis_agent import (
    AnalysisAgent, SequenceDetector, SequenceBuilder,
    MitreRAG, InterpretationEngine,
)
from analysis_agent.mitre_sample import SAMPLE_TECHNIQUES

# Étage 1 : entraîner le détecteur (sequences + labels binaires)
detector = SequenceDetector(recall_threshold=0.3)
detector.fit(train_sequences, train_labels)

# Étage 2 : RAG + LLM
rag = MitreRAG(); rag.index(SAMPLE_TECHNIQUES)
from ollama_llm import OllamaLLM
interpreter = InterpretationEngine(OllamaLLM(model="qwen3:4b"), rag)

# Agent complet
agent = AnalysisAgent(detector=detector, interpreter=interpreter)
outputs = agent.analyze(events)          # events = list[Event] du Collect Agent

for v in outputs.attacks():
    print(v.hypothesis)
    for t in v.techniques:
        print(t.technique_id, t.name, t.confidence)
```

Sans LLM (détection binaire seule) : `AnalysisAgent(detector=detector)` — l'Étage 2 est optionnel.

---

## Brancher les vraies données

### Windows-APT 2025 (Étage 1)
```bash
python run_with_windows_apt.py <dir_CSV> [mitre_matrix.json] [llm_model]
```
**À adapter** : `load_windows_apt()` (mapping des colonnes Wazuh → Event) et le chargement du `scenario_manifest.csv` pour les labels MITRE.

⚠️ Labels via règles Wazuh → **jeu de test indépendant** (scénarios Caldera propres) obligatoire.

### Vrai LLM (Étage 2)
```python
from ollama_llm import OllamaLLM
llm = OllamaLLM(model="qwen3:4b")     # ou phi4-mini, etc.
```
Ollama en CPU, gratuit. Variante `OpenAICompatLLM` pour vLLM/LM Studio.

### Vrai MITRE (RAG)
Remplacer `mitre_sample` par le vrai `mitre_matrix.json` (fourni avec CAM-LDS), via `load_mitre_matrix()`.

### Meilleur embedding (RAG)
TF-IDF par défaut (léger). En production, implémenter `EmbeddingModel` avec sentence-transformers pour une meilleure compréhension sémantique → meilleur rappel des techniques.

---

## État et limites (honnête)

**Fonctionnel et testé (données synthétiques)** :
- ✅ Sequence builder — regroupe par filiation, sépare le bruit, gère les cas durs.
- ✅ Étage 1 (ML) — mécanique validée, seuil orienté rappel fonctionnel.
- ✅ RAG MITRE — récupère les techniques candidates (5/6 sur l'exemple, TF-IDF).
- ✅ Étage 2 (LLM) — structure complète, anti-hallucination double barrière validée.
- ✅ Assemblage Option C — ML filtre → LLM interprète le suspect uniquement.

**À confirmer sur données réelles** :
- ⚠️ Performance du ML de détection (le test synthétique est trop tranché — le vrai compromis rappel/précision viendra de Windows-APT 2025).
- ⚠️ Qualité du raisonnement LLM (testé avec un LLM simulé ; le vrai modèle via Ollama).
- ⚠️ Rappel du RAG avec un vrai embedding sémantique (TF-IDF est un plancher).

---

## Prochaines étapes

1. Adapter `load_windows_apt()`, entraîner l'Étage 1.
2. Brancher Ollama (Qwen3/Phi-4) et le vrai `mitre_matrix.json`.
3. Jeu de test indépendant (Caldera) ; mesurer détection ET MITRE (top-k) séparément.
4. Intégrer avec le Collect Agent (ses `enriched` → Event).
