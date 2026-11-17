"""
Agentic Layer — couche agentique du Niveau 1.

Transforme le pipeline de détecteurs en un véritable SYSTÈME MULTI-AGENTS :
les agents perçoivent activement, décident de leur propre stratégie, agissent,
et coopèrent — sans modifier leur cœur (détecteurs et décision auditables).

Deux capacités par agent :
    - AUTO-ADAPTATION : l'agent module son comportement selon ce qu'il perçoit.
    - INTERACTION : les agents se sollicitent via un bus de requêtes.

Composants :
    agent_bus              - bus de requêtes inter-agents (la fondation)
    agentic_collect        - Collect : vigilance adaptative + re-collecte + répond aux "gap ?"
    agentic_analysis       - Analysis : auto-approfondissement + demande "gap ?" au Collect
    agentic_anonymization  - Anonymization : cascade décidée + signalement proactif
    agentic_decision       - Decision : exécution outillée + re-sollicitation avant escalade

Capacités agentiques démontrées :
    - Perception active     (Analysis→Collect, Decision→Analysis)
    - Décision autonome      (vigilance, effort, approfondissement, politique d'action)
    - Action                 (Decision exécute réellement, sous politique)
    - Coopération            (bus, dans les deux sens : tirer et pousser)
    - Auditabilité préservée (journaux du bus, des décisions, des exécutions)
"""

from .agent_bus import (
    AgentBus, AgentRequest, AgentResponse, RequestType, BusLogEntry,
)
from .agentic_collect import AgenticCollectAgent, HostVigilance
from .agentic_analysis import AgenticAnalysisAgent, AgenticAnalysisConfig
from .agentic_anonymization import (
    AgenticAnonymizationAgent, AgenticAnonymizationConfig, EffortRecord,
)
from .agentic_decision import (
    AgenticDecisionAgent, AgenticDecisionConfig, ActionPolicy, ActionExecution,
)

__version__ = "0.1.0"

__all__ = [
    "AgentBus", "AgentRequest", "AgentResponse", "RequestType", "BusLogEntry",
    "AgenticCollectAgent", "HostVigilance",
    "AgenticAnalysisAgent", "AgenticAnalysisConfig",
    "AgenticAnonymizationAgent", "AgenticAnonymizationConfig", "EffortRecord",
    "AgenticDecisionAgent", "AgenticDecisionConfig", "ActionPolicy", "ActionExecution",
]
