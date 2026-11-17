# =============================================================================
# RAG MITRE UNIFIÉ (Windows + Cloud)
# =============================================================================
# Helper pour indexer les techniques MITRE des DEUX mondes dans un seul RAG, afin
# que l'interpréteur de l'Analysis Agent puisse nommer les techniques aussi bien
# endpoint (Windows/Sysmon) que cloud (CloudTrail).
#
# Sans cela, l'interpréteur ne connaît que les techniques Windows et laisse les
# attaques cloud "sans nom" (le RAG rejette toute technique cloud proposée par le
# LLM, via la barrière anti-hallucination).
#
# Usage :
#     from analysis_agent.unified_mitre import build_unified_rag
#     rag = build_unified_rag()          # Windows + Cloud
#     interpreter = InterpretationEngine(llm, rag)
# =============================================================================

from __future__ import annotations

from .mitre_rag import MitreRAG
from .mitre_sample import SAMPLE_TECHNIQUES


def load_cloud_techniques():
    """
    Charge les techniques MITRE cloud. Import tolérant : si le module cloud n'est
    pas sur le path, retourne une liste vide (le RAG reste Windows-only sans
    planter).
    """
    try:
        import importlib
        mod = importlib.import_module("cloud_adapter.mitre_cloud_sample")
        return list(mod.SAMPLE_CLOUD_TECHNIQUES)
    except Exception:
        # fallback : chargement par chemin de fichier
        import importlib.util, os
        here = os.path.dirname(__file__)
        candidates = [
            os.path.join(here, "..", "..", "..", "cloud_adapter", "cloud_adapter",
                         "mitre_cloud_sample.py"),
            os.path.join(here, "mitre_cloud_sample.py"),
        ]
        for path in candidates:
            if os.path.exists(path):
                try:
                    spec = importlib.util.spec_from_file_location(
                        "mitre_cloud_sample", path)
                    m = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(m)
                    return list(m.SAMPLE_CLOUD_TECHNIQUES)
                except Exception:
                    return []
        return []


def build_unified_rag(include_cloud: bool = True) -> MitreRAG:
    """
    Construit un RAG MITRE indexant les techniques Windows et (optionnellement)
    cloud. C'est la façon recommandée de créer le RAG de l'Analysis Agent pour
    couvrir les deux mondes.
    """
    techniques = list(SAMPLE_TECHNIQUES)
    if include_cloud:
        techniques = techniques + load_cloud_techniques()
    rag = MitreRAG()
    rag.index(techniques)
    return rag
