"""
Decision Agent — frontière Niveau 1 / Niveau 2.

Composant d'un système multi-agents pour la sécurité cloud.
Corrèle les signaux des trois agents de détection (Analysis, Anonymization,
Collect), évalue la certitude, et produit un DOUBLE flux :
    - CONFIRMÉ → actions proposées à l'utilisateur (générateur d'actions, IA)
    - ESCALADÉ → dossier transmis au Niveau 2 (géolocalisation / investigation)

Les deux peuvent coexister (contenir ET localiser en parallèle).

Modèle décisionnel à DEUX DIMENSIONS (certitude/action + escalade), en RÈGLES
EXPLICITES et auditables. L'IA est réservée au seul générateur d'actions
(LLM léger + D3FEND/ATT&CK, avec raffinement par artefacts observés).

Modules :
    decision_schema       - signaux normalisés + entité corrélée
    signal_normalizers    - traduit les 3 sources vers le signal commun
    correlator            - regroupe les signaux par entité (host/IP/fenêtre)
    certainty_evaluator   - cœur décisionnel (2 dimensions, règles)
    defense_knowledge     - base D3FEND + ATT&CK (mapping technique→défenses)
    action_generator      - générateur d'actions (le seul module IA)
    level2_router         - prépare le dossier d'escalade Niveau 2
    decision_agent        - orchestrateur (pipeline complet)
"""

from .decision_schema import (
    NormalizedSignal, SignalSource, SignalKind, CorrelatedEntity,
)
from .signal_normalizers import (
    normalize_threat, normalize_anonymization, normalize_gap,
    normalize_integrity_flag, normalize_all,
)
from .correlator import Correlator, CorrelatorConfig
from .certainty_evaluator import (
    CertaintyEvaluator, CertaintyConfig, Decision,
    CertaintyLevel, EscalationMission,
)
from .defense_knowledge import (
    DefenseKnowledgeBase, DefensiveAction, TechniqueDefenses,
    ARTIFACT_TO_D3FEND, SAMPLE_DEFENSE_DB,
)
from .defense_loader import (
    build_defense_db, load_db, save_db, TECHNIQUES_SYSTEME,
)
from .integrity_score import (
    IntegrityCalibration, fit_calibration, score_window, windows_to_integrity_flags,
)
from .action_generator import (
    ActionGenerator, ActionPlan, RecommendedAction, LLMClient,
    build_action_prompt, parse_action_response,
)
from .level2_router import Level2Router, Level2Dossier
from .decision_agent import (
    DecisionAgent, DecisionOutputs, EntityOutcome,
)

__version__ = "0.1.0"

__all__ = [
    "NormalizedSignal", "SignalSource", "SignalKind", "CorrelatedEntity",
    "normalize_threat", "normalize_anonymization", "normalize_gap",
    "normalize_integrity_flag", "normalize_all",
    "Correlator", "CorrelatorConfig",
    "CertaintyEvaluator", "CertaintyConfig", "Decision",
    "CertaintyLevel", "EscalationMission",
    "DefenseKnowledgeBase", "DefensiveAction", "TechniqueDefenses",
    "build_defense_db", "load_db", "save_db", "TECHNIQUES_SYSTEME",
    "IntegrityCalibration", "fit_calibration", "score_window",
    "windows_to_integrity_flags",
    "ARTIFACT_TO_D3FEND", "SAMPLE_DEFENSE_DB",
    "ActionGenerator", "ActionPlan", "RecommendedAction", "LLMClient",
    "build_action_prompt", "parse_action_response",
    "Level2Router", "Level2Dossier",
    "DecisionAgent", "DecisionOutputs", "EntityOutcome",
]
