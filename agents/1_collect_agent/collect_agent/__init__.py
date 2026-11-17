"""
Collect Agent — gardien de l'intégrité des données.

Composant d'un système multi-agents pour la sécurité cloud.
Détecte les anomalies de DONNÉES (malformés, falsification, gaps),
pas les attaques. Normalise les logs vers un schéma canonique
agnostique de la source (endpoint Sysmon aujourd'hui, cloud demain).

Modules :
    canonical_schema       - schéma pivot (CanonicalLog)
    sysmon_mapper          - Sysmon brut → canonique + détection malformés
    forensic_rules         - détection de falsification connue (règles)
    gap_detection          - détection de suppression (gaps)
    falsification_generator- génération de falsifications (jeu de test)
    feature_extraction     - features pour le ML
    anomaly_ml             - ML d'anomalie (falsification inattendue)
    collect_agent          - orchestrateur (pipeline complet)
"""

from .canonical_schema import (
    CanonicalLog, ValidationResult, SourceType, ActivityCategory, Outcome,
    Actor, Target, ProcessContext, CloudContext,
)
from .sysmon_mapper import map_sysmon_event, SYSMON_EVENT_MAP
from .forensic_rules import ForensicRuleEngine, TamperType, TamperFinding
from .gap_detection import GapDetectionEngine, GapType, GapFinding
from .falsification_generator import (
    FalsificationGenerator, FalsificationType, FalsifiedDataset,
)
from .feature_extraction import extract_features, extract_matrix, FEATURE_NAMES
from .anomaly_ml import AnomalyDetector, AnomalyFinding
from .collect_agent import (
    CollectAgent, CollectOutputs, EnrichedLog, FlowRecord,
    RejectedLog, IntegrityAnnotation,
)

__version__ = "0.1.0"

__all__ = [
    "CanonicalLog", "ValidationResult", "SourceType", "ActivityCategory", "Outcome",
    "Actor", "Target", "ProcessContext", "CloudContext",
    "map_sysmon_event", "SYSMON_EVENT_MAP",
    "ForensicRuleEngine", "TamperType", "TamperFinding",
    "GapDetectionEngine", "GapType", "GapFinding",
    "FalsificationGenerator", "FalsificationType", "FalsifiedDataset",
    "extract_features", "extract_matrix", "FEATURE_NAMES",
    "AnomalyDetector", "AnomalyFinding",
    "CollectAgent", "CollectOutputs", "EnrichedLog", "FlowRecord",
    "RejectedLog", "IntegrityAnnotation",
]
