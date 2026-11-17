# Cloud Adapter — couche d'adaptation cloud

Rend le système multi-agents **adaptatif à n'importe quel cloud**, par le pattern **adaptateur** : un adaptateur par cloud traduit son format natif vers le **schéma canonique**. Le reste du système (les 4 agents) ne change **jamais** — il ne voit que du canonique.

```
AWS CloudTrail  ──┐
Azure Activity  ──┼──► ADAPTATEUR (par cloud) ──► CanonicalLog ──► les 4 agents
GCP Audit Logs  ──┘         (traduit le format)      (inchangé)
```

Pour supporter un nouveau cloud : écrire **un** adaptateur, ne toucher à rien d'autre. C'est une architecture **ouverte**, pas un système magiquement universel — la réponse honnête et défendable à « adaptatif à n'importe quel cloud ».

---

## Ce qui est fourni

- **`CloudAdapter`** : l'interface commune (contrat de tout adaptateur).
- **`AwsCloudTrailAdapter`** : l'implémentation AWS CloudTrail (format `Records[]`, `.json` et `.json.gz`).
- **`CloudAdapterRegistry`** : sélectionne le bon adaptateur selon le provider (extensible Azure/GCP).
- **`process_canonical_logs`** : le pont qui injecte les logs cloud dans le pipeline d'intégrité du Collect Agent.
- **`CloudSequenceBuilder`** : regroupe les événements cloud en séquences par **acteur + session** (la clé de corrélation cloud, remplaçant le ProcessGUID). Produit les mêmes `Sequence` que le builder Windows → l'Analysis Agent fonctionne sans modification.
- **`canonical_to_cloud_events`** : convertit le canonique cloud en `Event` de l'Analysis Agent.


---

## La clé de corrélation cloud (le point important)

Le cloud n'a **pas de ProcessGUID** (la clé de corrélation de Windows). L'adaptateur le remplace par **`userIdentity` + session** : `arn`/`principalId` + `sessionContext.creationDate`. Les événements d'un même acteur/session forment une séquence — exactement comme les processus Windows par filiation. Le sequence builder cloud (à venir) s'appuiera dessus.

---

## Ce que chaque agent retrouve dans le canonique cloud

| Agent | Ce qu'il lit | Source CloudTrail |
|---|---|---|
| Collect | intégrité (falsification/gaps) | `StopLogging`/`DeleteTrail` = manipulation du logging ; sauts d'événements = suppression |
| Analysis | séquences d'attaque | `userIdentity`/session (corrélation) + `eventName` (action) |
| Anonymization | origine des appels | `sourceIPAddress` (préservé sur chaque événement) |
| Decision | techniques MITRE for Cloud | dérivées de `eventName` + contexte |

Le **pont sémantique** (ActivityCategory) unifie : `AttachUserPolicy` (cloud) et une modif Windows sont tous deux `CONFIG_CHANGE`. Les agents ne savent pas d'où vient le log.

---

## Mode replay vs temps réel

`AwsCloudTrailAdapter(replay_mode=True)` (défaut) : pour les **données historiques** (datasets comme flaws.cloud, forensique). Aligne `ingest_time` sur `event_time` pour éviter les faux positifs de « clock skew » (l'écart entre l'événement de 2018 et le rejeu d'aujourd'hui n'est pas une falsification).

`replay_mode=False` : pour un **flux temps réel** (ingestion en direct), où le clock skew redevient un signal de falsification pertinent.

---

## Utilisation

```python
from cloud_adapter import AwsCloudTrailAdapter, process_canonical_logs

# 1. traduire le CloudTrail
adapter = AwsCloudTrailAdapter(replay_mode=True)
canonical = adapter.parse_file("cloudtrail.json.gz")   # ou .parse(json_str)

# 2. intégrité via le Collect Agent (réutilise ses moteurs)
from collect_agent.collect_agent import CollectAgent
collect = CollectAgent()
outputs = process_canonical_logs(collect, canonical)
print(collect.stats, outputs.gaps)
```

---

## Brancher flaws.cloud (données réelles, sans compte cloud)

flaws.cloud / flaws2.cloud : CTF AWS aux logs CloudTrail **publics et téléchargeables**.

```bash
# récupérer les logs de flaws2.cloud (bucket public)
aws s3 sync --no-sign-request s3://flaws2-logs/ ./flaws2_logs/

export PYTHONPATH=/chemin/vers/1_collect_agent
python run_with_flaws_cloud.py ./flaws2_logs/
```

**Vérité terrain (anti-circularité)** : les scénarios d'attaque de chaque niveau sont **documentés publiquement** (write-ups). On dérive les labels MITRE de cette documentation, **pas d'un LLM** — ce qui évite d'évaluer un LLM avec des labels produits par un LLM. Un LLM peut aider au pré-tri, mais la vérité terrain vient des write-ups ou d'une revue manuelle.

---

## État et limites (honnête)

**Fonctionnel et testé** :
- ✅ Adaptateur CloudTrail → canonique (format réel vérifié sur la doc AWS).
- ✅ Clé de corrélation cloud (session/principal).
- ✅ Pont vers le Collect Agent : détection d'intégrité sur le cloud (gaps, StopLogging).
- ✅ Registre multi-cloud (extensible Azure/GCP).
- ✅ Mode replay (pas de faux clock skew sur données historiques).

**À faire** :
- ⚠️ Sequence builder cloud (corrélation par session) pour l'Analysis Agent.
- ⚠️ RAG MITRE **for Cloud** (techniques cloud au lieu de Windows).
- ⚠️ Adaptateurs Azure (Activity Log) et GCP (Audit Logs).
- ⚠️ Validation sur le vrai flaws.cloud (le format est géré ; à confirmer sur volume).

**Note** : les datasets cloud publics sont modestes (flaws.cloud). Excellent pour **construire et valider** le pipeline cloud et comme jeu de test réaliste, mais léger pour *entraîner* un détecteur robuste — pour ça, générer davantage (Stratus Red Team, avec un compte sandbox).
