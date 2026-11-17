# Agentic Layer — couche agentique du Niveau 1

Cette couche transforme le pipeline de détecteurs spécialisés en un véritable **système multi-agents** : les agents perçoivent activement, décident de leur propre stratégie, agissent, et **coopèrent** — sans modifier leur cœur (les détecteurs et la décision restent tels quels, auditables).

C'est la réponse à la critique « c'est un pipeline, pas des agents » : on ajoute les propriétés agentiques (autonomie, perception→décision→action, coopération) **par-dessus** les composants existants.

---

## Le principe

Un **module** fait : `entrée → transformation → sortie` (toujours pareil).
Un **agent** fait : `perçois → décide quoi faire → agis` (marge de manœuvre selon ce qu'il observe).

Chaque agent gagne **deux capacités** :
- **Auto-adaptation** : il module son propre comportement selon ce qu'il perçoit.
- **Interaction** : il sollicite les autres agents via un **bus de requêtes**.

---

## Le bus de requêtes (la fondation)

Les agents ne communiquent plus par un flux unidirectionnel figé. Ils postent des **requêtes typées** sur un bus, qui les route vers l'agent capable de répondre. Découplé (les agents ne se connaissent pas en dur), traçable (tout échange est journalisé — auditable).

Types de requêtes : `check_gap`, `recollect`, `attention_hint`, `reanalyze`, `execute_action`.

Bus **en mémoire** (synchrone) : suffit à démontrer l'agentivité, reste testable. Remplaçable par une vraie file (Redis, Kafka) en production sans changer le code des agents.

---

## Les quatre agents agentiques

| Agent | Auto-adaptation | Interaction |
|---|---|---|
| **Collect** | vigilance accrue sur un host après falsification (seuil de silence resserré) | re-collecte ciblée d'un gap ; répond aux requêtes « gap ? » |
| **Analysis** | approfondit quand le score est incertain (merge_by_session) | demande au Collect « gap sur ce host ? » |
| **Anonymization** | cascade décidée (lookup→GNN→Anomal-E selon l'incertitude) | prévient l'Analysis « anonymisation ici, regarde » |
| **Decision** | politique d'exécution (manuel / immediate / autonome) | exécute les actions (outils) ; re-sollicite les détecteurs avant d'escalader |

Chaque agent est un **wrapper** qui enveloppe le cœur existant — le cœur n'est jamais modifié.

---

## Les capacités agentiques démontrées

- **Perception active** : les agents vont chercher l'information (Analysis→Collect, Decision→Analysis).
- **Décision autonome sur la stratégie** : chacun ajuste son comportement (vigilance, effort de calcul, approfondissement).
- **Action** : le Decision exécute réellement (blocage, isolation), sous contrôle d'une politique.
- **Coopération dans les deux sens** : *tirer* l'info quand on doute, *pousser* l'info quand on détecte.
- **Auditabilité préservée** : journaux du bus, des décisions, des exécutions.

### Exemple de coopération (Analysis ↔ Collect)
Une attaque tronquée par une suppression de logs :
1. Le Collect détecte le gap et le mémorise.
2. L'Analysis reçoit une séquence incomplète, score incertain (0.41).
3. Au lieu d'un verdict tiède, il **demande au Collect** : gap sur ce host ?
4. Le Collect confirme → l'incomplétude s'explique (logs supprimés).
5. L'Analysis **relève sa suspicion** (0.41 → 0.66) → attaque détectée.

Sans coopération, l'attaque passait sous le radar.

---

## Structure

```
agentic_layer/
    __init__.py
    agent_bus.py               bus de requêtes inter-agents
    agentic_collect.py         couche agentique du Collect
    agentic_analysis.py        couche agentique de l'Analysis
    agentic_anonymization.py   couche agentique de l'Anonymization
    agentic_decision.py        couche agentique du Decision
tests/                         un test par couche (+ coopération)
```

---

## Utilisation

```python
from agentic_layer import AgentBus, AgenticCollectAgent, AgenticAnalysisAgent

bus = AgentBus()

# envelopper les cœurs existants
collect = AgenticCollectAgent(collect_core, bus, recollect_source=ma_source)
analysis = AgenticAnalysisAgent(analysis_core, bus,
    builder_cls=SequenceBuilder, builder_config_cls=SequenceBuilderConfig)

# les agents coopèrent automatiquement via le bus
collect.process_batch(logs)      # mémorise les gaps
analysis.analyze(events)         # demande au Collect en cas de doute

# traçabilité (pour la thèse)
print(bus.interactions())        # le journal de coopération
print(analysis.decisions_report())
```

---

## Note de conception (défense pour le jury)

Le cœur décisionnel du **Decision Agent reste en règles explicites**, pas un LLM autonome — c'est un choix assumé : les décisions à conséquence réelle doivent être auditables. La couche agentique agit *autour* de la décision (exécution outillée, re-sollicitation), pas *à la place* du raisonnement auditable.

On obtient ainsi **les deux** : décision explicable **et** comportement agentique (autonomie, action, coopération).
