#!/usr/bin/env python3
"""
Point d'entrée : brancher Windows-APT 2025 sur l'Analysis Agent.

Workflow avec de VRAIES données :
  1. charger Windows-APT 2025 (CSV Wazuh) + le scenario_manifest (mapping MITRE)
  2. convertir les logs en Event (contrat d'entrée)
  3. construire les séquences (sequence builder)
  4. entraîner l'Étage 1 (ML de détection) sur les labels binaires attaque/normal
  5. brancher l'Étage 2 (LLM Ollama + RAG MITRE réel)
  6. évaluer : détection (binaire) ET attribution MITRE (top-k) SÉPARÉMENT

À ADAPTER :
  - load_windows_apt() : format exact des CSV Windows-APT 2025
  - le mapping des champs Wazuh → Event
  - charger le vrai mitre_matrix.json à la place de mitre_sample

IMPORTANT (rappels de conception) :
  - labels via règles Wazuh → jeu de TEST INDÉPENDANT obligatoire (Caldera propre)
  - viser le TOP-K pour MITRE, pas le top-1
  - mesurer détection et MITRE séparément
"""
import sys
import json
from pathlib import Path

from analysis_agent import (
    Event, EventCategory, SequenceBuilder, SequenceDetector,
    MitreRAG, MitreTechnique, InterpretationEngine, AnalysisAgent,
)


def load_mitre_matrix(path: str) -> list[MitreTechnique]:
    """
    Charge le vrai mitre_matrix.json (fourni avec CAM-LDS).
    ADAPTE selon sa structure exacte.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    techniques = []
    # structure supposée : liste d'objets {id, name, tactic, description}
    items = data if isinstance(data, list) else data.get("techniques", [])
    for it in items:
        techniques.append(MitreTechnique(
            technique_id=it.get("id") or it.get("technique_id", ""),
            name=it.get("name", ""),
            tactic=it.get("tactic") or it.get("tactic_name", ""),
            description=it.get("description", ""),
            keywords=it.get("keywords", []),
        ))
    return techniques


def load_windows_apt(csv_dir: str) -> tuple[list[Event], dict]:
    """
    Charge Windows-APT 2025 et convertit en Event.

    À ADAPTER : Windows-APT 2025 est en CSV (collecte Wazuh). Il faut mapper
    les colonnes vers Event (event_time, process_guid, parent_process_guid,
    process_name, command_line, destination_ip, etc.).

    Retourne (events, labels) où labels associe une séquence/scénario à
    ses techniques MITRE (via scenario_manifest.csv).
    """
    import pandas as pd
    events: list[Event] = []
    # ... mapping à implémenter après inspection des CSV réels ...
    # Exemple de structure attendue :
    # for _, row in df.iterrows():
    #     events.append(Event(
    #         event_id=row["id"],
    #         event_time=pd.to_datetime(row["timestamp"]),
    #         category=map_category(row["event_type"]),
    #         host=row["agent_name"],
    #         process_guid=row.get("process_guid"),
    #         parent_process_guid=row.get("parent_guid"),
    #         process_name=row.get("process_name"),
    #         command_line=row.get("command_line"),
    #         destination_ip=row.get("dst_ip"),
    #     ))
    raise NotImplementedError(
        "Adapte load_windows_apt() au format réel des CSV Windows-APT 2025 "
        "(inspecte les colonnes, mappe vers Event, utilise scenario_manifest.csv "
        "pour les labels MITRE)."
    )


def main(csv_dir: str, mitre_path: str, llm_model: str = None):
    print("[1] Chargement du RAG MITRE ...")
    if mitre_path:
        techniques = load_mitre_matrix(mitre_path)
    else:
        from analysis_agent.mitre_sample import SAMPLE_TECHNIQUES
        techniques = SAMPLE_TECHNIQUES
        print("    (échantillon d'exemple — fournis mitre_matrix.json pour le réel)")
    rag = MitreRAG(); rag.index(techniques)
    print(f"    {len(techniques)} techniques indexées")

    print("[2] Chargement de Windows-APT 2025 ...")
    events, labels = load_windows_apt(csv_dir)
    print(f"    {len(events)} événements")

    print("[3] Construction des séquences ...")
    builder = SequenceBuilder()
    sequences = builder.build(events)
    print(f"    {len(sequences)} séquences")

    # [4] entraîner le détecteur (labels binaires attaque/normal)
    # [5] brancher le LLM
    interpreter = None
    if llm_model:
        from ollama_llm import OllamaLLM
        interpreter = InterpretationEngine(OllamaLLM(model=llm_model), rag)

    # ... entraînement + évaluation (détection + MITRE top-k séparés) ...
    print("[!] Complète l'entraînement et l'évaluation après avoir adapté le chargement.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python run_with_windows_apt.py <dir_CSV> [mitre_matrix.json] [llm_model]")
        sys.exit(1)
    csv_dir = sys.argv[1]
    mitre_path = sys.argv[2] if len(sys.argv) > 2 else None
    llm_model = sys.argv[3] if len(sys.argv) > 3 else None
    main(csv_dir, mitre_path, llm_model)
