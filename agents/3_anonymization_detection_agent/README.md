# Anonymization Detection Agent — détection d'anonymisation (VPN/Tor)

Composant d'un système multi-agents pour la sécurité cloud (thèse « Agentic System for Cloud Security and Anonymization Detection »).

Le Anonymization Detection Agent tranche, de façon **binaire**, si un flux réseau utilise une technique d'**anonymisation** (VPN ou Tor). La géolocalisation probabiliste elle-même est déléguée à un niveau supérieur (hors de cet agent).

---

## Architecture en cascade

```
flux réseau
   │
   ▼  ÉTAPE 1 — lookup (l'IP suffit)
   │     listes Tor + bases VPN/ASN
   │     └── IP connue → verdict immédiat (conf 0.99)   [STOP]
   ▼  ÉTAPE 2 — GNN E-GraphSAGE (flux inconnus du lookup)
   │     nœuds = IP, arêtes = flux, features sur les arêtes
   │     └── verdict : normal / VPN / Tor
   ▼  (optionnel) Anomal-E en filet
         E-GraphSAGE=normal mais Anomal-E=anormal
         → flag "anonymisation inconnue possible"
```

**E-GraphSAGE décide** (moteur de production). **Anomal-E** sert à deux choses : l'**ablation anti-circularité** (prouver qu'on atteint presque le supervisé sans labels) et un **filet** optionnel pour les anonymiseurs inconnus.

---

## Ce qu'il détecte, et la difficulté réelle

| Cible | Difficulté | Performance attendue |
|---|---|---|
| **Tor** | Facile (signature distincte) | ~0.98 |
| **VPN** | **Dure** (ressemble au trafic normal) | ~0.78 |

**Règle absolue : mesurer Tor et VPN SÉPARÉMENT.** Un F1 agrégé « anonymisation » masque le vrai point faible (le VPN). Le code d'évaluation sépare toujours les deux.

---

## Structure du package

```
geolocation_agent/
    __init__.py                 API publique
    flow_schema.py              contrat d'entrée (NetworkFlow, FlowFeatures)
    lookup_engine.py            étape 1 (Tor/VPN connus)
    darknet_preprocessing.py    préparation de CIC-Darknet2020
    graph_builder.py            construction du graphe de flux
    egraphsage.py               GNN supervisé (moteur de décision)
    anomale.py                  GNN self-supervised (ablation / filet)
    geolocation_agent.py        orchestrateur (cascade complète)
run_with_darknet.py             point d'entrée avec de vraies données
example_minimal.py              exemple minimal
tests/                          tests de chaque brique
```

---

## Installation

```bash
pip install torch pandas scikit-learn numpy networkx
```

Python 3.12+.

---

## Utilisation rapide

### Lookup seul (sans GNN, immédiat)

```python
from anonymization_detection_agent import AnonymizationDetectionAgent, LookupEngine, TorExitList, VpnRangeDb, NetworkFlow

tor = TorExitList(); tor.load(["185.220.101.99"])
vpn = VpnRangeDb(); vpn.add_range("45.83.220.0/22")
agent = AnonymizationDetectionAgent(lookup=LookupEngine(tor_list=tor, vpn_db=vpn))

flows = [NetworkFlow(flow_id="F1", src_ip="10.0.0.5", dst_ip="185.220.101.99")]
for v in agent.analyze_batch(flows):
    print(v.label.value, v.method, v.confidence)   # tor lookup 0.99
```

### Avec le GNN (après entraînement sur CIC-Darknet2020)

```python
from anonymization_detection_agent import AnonymizationDetectionAgent, GraphBuilder, train_egraphsage

model = train_egraphsage(graph, train_mask, val_mask, epochs=200, class_weights=cw)
agent = AnonymizationDetectionAgent(lookup=lookup, egraphsage_model=model, graph_builder=GraphBuilder())
verdicts = agent.analyze_batch(flows)   # lookup + GNN en cascade
```

---

## Brancher CIC-Darknet2020 (données réelles)

```bash
python run_with_darknet.py /chemin/vers/Darknet.csv
```

Le script : charge (brut) → prépare → construit le graphe → entraîne E-GraphSAGE **et** Anomal-E → évalue **Tor et VPN séparément**.

### ⚠️ Points critiques

1. **Fichier BRUT obligatoire.** Utilise `Darknet.csv` (avec `Src IP` / `Dst IP`). Les versions « preprocessed » de Kaggle **suppriment les IP** → le graphe devient impossible. Le préprocesseur **refuse** un fichier sans IP avec un message clair.

2. **Défauts du dataset gérés automatiquement** : déduplication (évite la fuite train/test), nettoyage des valeurs infinies CICFlowMeter, mesure du déséquilibre (Tor ultra-minoritaire), option de rééquilibrage.

3. **Compatibilité des features (sonde).** Le GNN est entraîné sur les features de CIC-Darknet2020. En production, la sonde (tshark + CICFlowMeter) doit produire le **même TYPE de features** — pas identiques au bit près, mais les mêmes colonnes. Vérifier que les noms de colonnes correspondent.

---

## État et limites (honnête)

**Fonctionnel et testé (données synthétiques)** :
- ✅ Contrat de flux (identité + features).
- ✅ Étape 1 (lookup) — Tor/VPN connus détectés, inconnus passés au GNN.
- ✅ Préparation CIC-Darknet2020 — garde-fou IP, déduplication, déséquilibre.
- ✅ Construction du graphe — format E-GraphSAGE (features sur arêtes).
- ✅ E-GraphSAGE — apprend, reproduit le constat Tor≫VPN (F1 Tor 1.0 / VPN 0.69 en synthétique).
- ✅ Anomal-E — self-supervised, atteint presque le supervisé SANS labels (AUROC Tor 0.998 / VPN 0.680).
- ✅ Assemblage — cascade lookup → GNN validée.

**À confirmer sur CIC-Darknet2020 (les chiffres définitifs)** :
- ⚠️ Les performances réelles Tor/VPN. Les chiffres synthétiques prouvent que l'architecture **discrimine** (contrairement à un modèle qui échouerait), mais les vrais chiffres viennent du dataset réel.
- ⚠️ La compatibilité exacte des features sonde ↔ dataset.

**Prévu** :
- 🔲 Intégration avec la **sonde de capture** (tshark + CICFlowMeter) pour la production.

---

## Prochaines étapes

1. Télécharger CIC-Darknet2020 **brut**, lancer `run_with_darknet.py`.
2. Comparer E-GraphSAGE vs Anomal-E (ablation anti-circularité).
3. Mesurer Tor et VPN séparément ; rapporter honnêtement le VPN.
4. Intégrer la sonde pour la production.

---

## Lancer les tests

```bash
cd package
PYTHONPATH=. python3 tests/test_lookup.py
PYTHONPATH=. python3 tests/test_prep_graph.py
PYTHONPATH=. python3 tests/test_gnn.py
PYTHONPATH=. python3 tests/test_anomale.py
PYTHONPATH=. python3 tests/test_agent_complet.py
```
