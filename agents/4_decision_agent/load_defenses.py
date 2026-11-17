#!/usr/bin/env python3
"""
Chargement des vraies bases de défenses (D3FEND + ATT&CK Mitigations).

À télécharger UNE FOIS et stocker en local (pas de dépendance à l'API en ligne) :
  - d3fend-full-mappings.json
      depuis https://d3fend.mitre.org/api/ontology/inference/d3fend-full-mappings.json
  - les mitigations ATT&CK (déjà dans mitre_matrix.json de l'Analysis Agent,
    ou depuis le STIX ATT&CK)

Ce script construit la DefenseKnowledgeBase à partir de ces fichiers.
À ADAPTER selon la structure exacte des fichiers téléchargés.

Usage :
    from load_defenses import build_defense_db
    kb = build_defense_db("d3fend-full-mappings.json", "attack_mitigations.json")
"""
import json
from pathlib import Path

from decision_agent import (
    DefenseKnowledgeBase, DefensiveAction, TechniqueDefenses,
)


def load_d3fend_mappings(path: str) -> dict:
    """
    Charge d3fend-full-mappings.json → {technique_id: [DefensiveAction]}.

    ADAPTE le parsing selon la structure réelle du JSON D3FEND. Le mapping relie
    une technique ATT&CK à des techniques défensives D3FEND via les artefacts.
    Structure attendue (à vérifier) : entrées reliant off_technique → def_technique
    avec l'artefact intermédiaire.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    result: dict[str, list[DefensiveAction]] = {}

    # Le format exact varie ; on gère une structure de type liste de mappings.
    # ADAPTE ces clés après inspection d'un échantillon réel.
    mappings = data if isinstance(data, list) else data.get("mappings", data.get("results", []))
    for m in mappings:
        off = m.get("off_tech_id") or m.get("attack_id") or m.get("technique_id")
        if not off:
            continue
        action = DefensiveAction(
            action_id=m.get("def_tech_id") or m.get("d3fend_id", ""),
            name=m.get("def_tech_label") or m.get("d3fend_label", ""),
            source="d3fend",
            artifact=m.get("artifact") or m.get("digital_artifact"),
            description=m.get("def_tech_definition", "") or m.get("description", ""),
        )
        result.setdefault(off, []).append(action)
    return result


def load_attack_mitigations(path: str) -> dict:
    """
    Charge les mitigations ATT&CK → {technique_id: [DefensiveAction]}.
    ADAPTE selon la source (mitre_matrix.json enrichi ou STIX ATT&CK).
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    result: dict[str, list[DefensiveAction]] = {}
    items = data if isinstance(data, list) else data.get("techniques", [])
    for it in items:
        tid = it.get("id") or it.get("technique_id", "")
        for mit in it.get("mitigations", []):
            result.setdefault(tid, []).append(DefensiveAction(
                action_id=mit.get("id", ""),
                name=mit.get("name", ""),
                source="attack_mitigation",
                description=mit.get("description", ""),
            ))
    return result


def build_defense_db(d3fend_path: str = None,
                     attack_path: str = None) -> DefenseKnowledgeBase:
    """Construit la base de défenses locale à partir des fichiers réels."""
    d3fend = load_d3fend_mappings(d3fend_path) if d3fend_path else {}
    attack = load_attack_mitigations(attack_path) if attack_path else {}

    all_techniques = set(d3fend) | set(attack)
    db: dict[str, TechniqueDefenses] = {}
    for tid in all_techniques:
        db[tid] = TechniqueDefenses(
            technique_id=tid,
            d3fend_actions=d3fend.get(tid, []),
            attack_mitigations=attack.get(tid, []),
        )
    print(f"Base de défenses construite : {len(db)} techniques "
          f"({len(d3fend)} avec D3FEND, {len(attack)} avec mitigations ATT&CK)")
    return DefenseKnowledgeBase(db)


if __name__ == "__main__":
    import sys
    d3 = sys.argv[1] if len(sys.argv) > 1 else None
    at = sys.argv[2] if len(sys.argv) > 2 else None
    if not d3:
        print("Usage: python load_defenses.py <d3fend-full-mappings.json> [attack_mitigations.json]")
        print("Sans arguments, l'agent utilise l'échantillon SAMPLE_DEFENSE_DB.")
    else:
        kb = build_defense_db(d3, at)
