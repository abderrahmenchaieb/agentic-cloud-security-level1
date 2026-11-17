"""
Analysis Agent — détecteur de menaces par corrélation de séquences.

Composant d'un système multi-agents pour la sécurité cloud.
Sur des données saines (du Collect Agent), détecte les ATTAQUES par
corrélation de séquences multi-étapes. Architecture Option C :
    - Étage 1 (ML) : détecte attaque/normal, rapide, sur toutes les séquences
    - Étage 2 (LLM + RAG MITRE) : interprète SEULEMENT le suspect

Modules :
    sequence_schema        - Event, Sequence (contrat d'entrée)
    sequence_builder       - regroupement mécanique en séquences (ProcessGUID)
    sequence_features      - features de séquence pour l'Étage 1
    sequence_detector      - Étage 1 : ML de détection (orienté rappel)
    mitre_rag              - RAG MITRE (récupération des techniques candidates)
    mitre_sample           - échantillon de techniques (à remplacer par mitre_matrix.json)
    interpretation_engine  - Étage 2 : LLM + anti-hallucination
    analysis_agent         - orchestrateur (pipeline Option C)
"""

from .sequence_schema import Event, Sequence, EventCategory
from .sequence_builder import SequenceBuilder, SequenceBuilderConfig
from .sequence_features import extract_sequence_features, FEATURE_NAMES
from .sequence_detector import SequenceDetector, SequenceVerdict
from .mitre_rag import (
    MitreRAG, MitreTechnique, RetrievedTechnique,
    EmbeddingModel, TfidfEmbedding, sequence_to_query,
)
from .interpretation_engine import (
    InterpretationEngine, LLMClient, AttackInterpretation,
    AttributedTechnique, build_prompt, parse_response,
)
from .analysis_agent import AnalysisAgent, ThreatVerdict, AnalysisOutputs

__version__ = "0.1.0"

__all__ = [
    "Event", "Sequence", "EventCategory",
    "SequenceBuilder", "SequenceBuilderConfig",
    "extract_sequence_features", "FEATURE_NAMES",
    "SequenceDetector", "SequenceVerdict",
    "MitreRAG", "MitreTechnique", "RetrievedTechnique",
    "EmbeddingModel", "TfidfEmbedding", "sequence_to_query",
    "InterpretationEngine", "LLMClient", "AttackInterpretation",
    "AttributedTechnique", "build_prompt", "parse_response",
    "AnalysisAgent", "ThreatVerdict", "AnalysisOutputs",
]
