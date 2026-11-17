"""
Anonymization Detection Agent — détection d'anonymisation (VPN/Tor).

Composant d'un système multi-agents pour la sécurité cloud.
Tranche, de façon binaire, si un flux utilise une technique d'anonymisation.

Architecture en cascade :
    Étape 1 — lookup (IP connue : listes Tor + bases VPN/ASN)
    Étape 2 — GNN E-GraphSAGE (flux inconnus) ; Anomal-E en filet optionnel

Modules :
    flow_schema            - contrat d'entrée (NetworkFlow, FlowFeatures)
    lookup_engine          - étape 1 (Tor/VPN connus)
    darknet_preprocessing  - préparation de CIC-Darknet2020
    graph_builder          - construction du graphe de flux
    egraphsage             - GNN supervisé (moteur de décision)
    anomale                - GNN self-supervised (comparatif / filet)
    geolocation_agent      - orchestrateur (pipeline complet)
"""

from .flow_schema import (
    NetworkFlow, FlowFeatures, AnonymizationVerdict, AnonymizationLabel,
)
from .lookup_engine import LookupEngine, TorExitList, VpnRangeDb, LookupResult
from .darknet_preprocessing import DarknetPreprocessor, DatasetStats
from .graph_builder import GraphBuilder, FlowGraph, DEFAULT_EDGE_FEATURES
from .egraphsage import (
    EGraphSAGE, EGraphSAGELayer, train_egraphsage, graph_to_tensors,
)
from .anomale import AnomalEDGI, AnomalEDetector, train_anomale
from .anonymization_detection_agent import AnonymizationDetectionAgent, AnonymizationDetectionConfig

__version__ = "0.1.0"

__all__ = [
    "NetworkFlow", "FlowFeatures", "AnonymizationVerdict", "AnonymizationLabel",
    "LookupEngine", "TorExitList", "VpnRangeDb", "LookupResult",
    "DarknetPreprocessor", "DatasetStats",
    "GraphBuilder", "FlowGraph", "DEFAULT_EDGE_FEATURES",
    "EGraphSAGE", "EGraphSAGELayer", "train_egraphsage", "graph_to_tensors",
    "AnomalEDGI", "AnomalEDetector", "train_anomale",
    "AnonymizationDetectionAgent", "AnonymizationDetectionConfig",
]
