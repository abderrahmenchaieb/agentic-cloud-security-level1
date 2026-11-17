# Collect Agent — gardien de l'intégrité des données

Composant d'un système multi-agents pour la sécurité cloud (thèse « Agentic System for Cloud Security and Geolocation »).

Le Collect Agent **collecte, normalise et vérifie l'intégrité** des logs, puis produit des flux propres pour les agents en aval (Analysis, Geolocation). Il détecte des **anomalies de données** — il ne détecte **pas** d'attaques (c'est le rôle de l'Analysis Agent).

---

## Ce qu'il détecte

| Anomalie de données | Méthode | Module |
|---|---|---|
| **Logs malformés** (structure cassée) | Validation de schéma | `sysmon_mapper` |
| **Falsification connue** (timestomping, injection, réordonnancement) | Règles forensiques déterministes | `forensic_rules` |
| **Suppression** (logs manquants) | Détection de gaps (RecordNumber + silence) | `gap_detection` |
| **Falsification inattendue** | ML d'anomalie non-supervisé | `anomaly_ml` |

---

## Architecture du pipeline

```
log brut Sysmon
     │
     ▼  [1] mapper → canonique + détection MALFORMÉS
     │        └── malformé → rejected (STOP)
     ▼  [2] règles forensiques → FALSIFICATION connue
     ▼  [3] détection de GAPS → suppression
     ▼  [4] ML d'anomalie → FALSIFICATION inattendue (optionnel)
     │
     ▼  routage :
     ├── enriched  (log + annotations)      → Analysis Agent
     ├── flows     (si réseau)              → Geolocation Agent
     ├── gaps      (données manquantes)     → Analysis Agent
     └── rejected  (malformés)              → audit
```

**Principes** : l'agent **signale, ne décide pas** ; il ne **supprime jamais silencieusement** (tout malformé est tracé) ; il **s'auto-surveille** (statistiques de santé + détection de source coupée).

---

## Structure du package

```
collect_agent/
    __init__.py                  API publique
    canonical_schema.py          schéma pivot (agnostique source : endpoint + cloud)
    sysmon_mapper.py             Sysmon brut → canonique + malformés
    forensic_rules.py            règles de falsification (R1..R5)
    gap_detection.py             suppression (RecordNumber + silence)
    falsification_generator.py   génération de falsifications (jeu de test)
    feature_extraction.py        features pour le ML
    anomaly_ml.py                Isolation Forest non-supervisé
    collect_agent.py             orchestrateur (pipeline complet)
run_with_comiset.py              point d'entrée avec de vraies données
example_minimal.py               exemple minimal
tests/                           tests de chaque brique
```

---

## Installation

```bash
pip install pydantic scikit-learn numpy
```

Python 3.12+. Aucune autre dépendance.

---

## Utilisation rapide

```python
from collect_agent import CollectAgent

agent = CollectAgent()  # sans ML (règles + gaps seulement)

raw = {
    "EventID": 1, "UtcTime": "2025-06-01 10:00:00.100", "Computer": "VM-01",
    "ProcessGuid": "{g-1}", "Image": "powershell.exe",
    "CommandLine": "powershell -enc ...", "ParentProcessGuid": "{g-0}",
    "RecordNumber": "100",
}
agent.process(raw)

print(agent.outputs.summary())
for e in agent.outputs.enriched:
    if e.has_integrity_issue:
        print(e.log.event_id, [a.detail for a in e.annotations])
```

### Avec le ML activé (après entraînement sur un corpus intègre)

```python
from collect_agent import CollectAgent, AnomalyDetector
import numpy as np

detector = AnomalyDetector(contamination=0.05)
detector.fit(corpus_integre)                      # apprend le "normal" (sans labels)

scores = np.array([detector.score(l).raw_score for l in corpus_valid])
threshold = float(np.percentile(scores, 1))       # calibre le seuil

agent = CollectAgent(anomaly_detector=detector, ml_threshold=threshold)
```

---

## Brancher COMISET (données réelles)

COMISET (Zenodo, DOI 10.5281/zenodo.15375146) sert de **corpus de logs intègres** — on **n'utilise PAS ses labels MITRE** (produits par règles = circularité). On l'utilise comme base saine.

```bash
python run_with_comiset.py /chemin/vers/COMISET/
```

Le script fait : chargement → normalisation → entraînement ML → calibration → génération de falsifications → **ablation (règles vs règles+ML)** → agent complet.

**À ADAPTER** dans `run_with_comiset.py` :
- `load_comiset()` : format des fichiers (JSON array ou JSON-Lines).
- `normalize_comiset_fields()` : le mapping des champs. COMISET imbrique peut-être les champs Sysmon (ex : `winlog.event_data.*`). **Inspecte un échantillon réel** et ajuste le mapping. Vérifie notamment le nom du numéro de séquence (`EventRecordID` attendu).

### Corpus intègre (important)
COMISET contient des logs d'attaques. Pour un « normal » pur, il faut **filtrer les logs bénins** avant d'entraîner le ML (le ML doit apprendre le normal, pas l'attaque). Ce filtrage est à faire selon la structure de COMISET.

---

## État et limites (honnête)

**Fonctionnel et testé (données synthétiques)** :
- ✅ Schéma canonique — accueille endpoint (Sysmon) ET cloud (CloudTrail).
- ✅ Mapper + malformés — 3/3 valides, 5/5 malformés rejetés.
- ✅ Règles forensiques — 0 faux positif, falsifications connues détectées.
- ✅ Détection de gaps — saut RecordNumber, silence, source coupée.
- ✅ Générateur de falsifications — boucle fermée, rappel 91-100 % selon ratio.
- ✅ Assemblage complet — routage des 4 sorties validé.

**À valider sur COMISET (ne peut PAS être tranché sur données synthétiques)** :
- ⚠️ **La valeur ajoutée du ML.** Sur corpus synthétique, le ML ne discrimine pas (le « normal » aléatoire est trop dispersé). Le test décisif = ablation sur COMISET (voir `run_with_comiset.py`). Deux issues possibles, toutes deux défendables :
  - le ML attrape des falsifications que les règles ratent → valeur prouvée ;
  - le ML n'ajoute rien de significatif → les règles suffisent (résultat négatif à documenter).

**Extension prévue** :
- 🔲 Plan de contrôle **cloud** : le schéma est déjà prêt (`CloudContext`, `SourceType.CLOUD_CONTROL`). Il reste à écrire un `cloudtrail_mapper` sur le modèle de `sysmon_mapper`.

---

## Prochaines étapes

1. Télécharger COMISET, adapter `normalize_comiset_fields()`, lancer l'ablation.
2. Trancher la valeur du ML sur données réelles.
3. (Phase cloud) écrire le mapper CloudTrail/Azure/GCP.
4. Passer aux agents Analysis et Geolocation.

---

## Lancer les tests

```bash
cd package
PYTHONPATH=. python3 tests/test_schema.py
PYTHONPATH=. python3 tests/test_mapper.py
PYTHONPATH=. python3 tests/test_forensic.py
PYTHONPATH=. python3 tests/test_gaps.py
PYTHONPATH=. python3 tests/test_falsification2.py
```
