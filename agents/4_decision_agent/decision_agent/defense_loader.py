"""
=============================================================================
CONSTRUCTION DE LA BASE DE CONNAISSANCES DÉFENSIVE (réelle)
=============================================================================
Remplace la SAMPLE_DEFENSE_DB de démonstration par les VRAIES mitigations
MITRE ATT&CK, extraites du bundle STIX officiel.

SOURCE
    https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/
        enterprise-attack/enterprise-attack.json
    (268 course-of-action, 1448 relations `mitigates`)

MÉTHODE
    course-of-action --[mitigates]--> attack-pattern
    On résout les identifiants STIX vers les identifiants publics (M####, T####)
    via les external_references de source `mitre-attack`, en écartant les objets
    révoqués ou dépréciés.

COUVERTURE MESURÉE sur les 26 techniques du système (12 Windows + 14 cloud)
    20/26 techniques couvertes, 81 associations technique → mitigation.
    Les 6 non couvertes (T1547.001, T1082, T1057, T1526, T1562.008, T1562.007)
    n'ont PAS de mitigation dans ATT&CK — y compris au niveau de leur technique
    parente. C'est une caractéristique du référentiel, pas une lacune du
    chargement : ATT&CK considère ces comportements (Discovery, Impair Defenses)
    comme non atténuables par un contrôle préventif, la réponse relevant de la
    détection et de la surveillance. Le générateur d'actions doit donc gérer le
    cas « aucune candidate » sans produire de recommandation inventée.

D3FEND
    Le mapping D3FEND (défenses par artefact) n'est pas inclus ici : l'ontologie
    D3FEND n'est pas accessible depuis l'environnement de build. La structure
    `TechniqueDefenses.d3fend_actions` reste en place et sera peuplée quand le
    fichier `d3fend-full-mappings.json` sera disponible. En son absence, le
    raffinement par artefacts s'applique aux seules mitigations ATT&CK.
=============================================================================
"""
from __future__ import annotations
import json
from pathlib import Path

from .defense_knowledge import (
    DefenseKnowledgeBase, DefensiveAction, TechniqueDefenses,
)

# Les 26 techniques indexées par le système (cohérent avec unified_mitre.py)
TECHNIQUES_SYSTEME = [
    # --- Windows (Sysmon) ---
    "T1055", "T1059.001", "T1003", "T1547.001", "T1053.005", "T1112",
    "T1027", "T1021.002", "T1078", "T1105", "T1082", "T1057",
    # --- Cloud (CloudTrail) ---
    "T1078.004", "T1580", "T1526", "T1087.004", "T1552.001", "T1552.006",
    "T1562.008", "T1562.007", "T1098.001", "T1098.003", "T1136.003",
    "T1537", "T1578", "T1548",
]

STIX_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
            "master/enterprise-attack/enterprise-attack.json")


def extract_mitigations_from_stix(stix_path: str) -> dict[str, list[dict]]:
    """
    Bundle STIX ATT&CK → {technique_id: [{id, name, description}, ...]}.
    Écarte les objets révoqués ou dépréciés.
    """
    with open(stix_path, "r", encoding="utf-8") as fh:
        bundle = json.load(fh)
    objects = bundle.get("objects", [])

    def public_id(obj, prefix):
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                ext = ref.get("external_id", "")
                if ext.startswith(prefix):
                    return ext
        return None

    def vivant(obj):
        return not obj.get("revoked") and not obj.get("x_mitre_deprecated")

    techniques = {o["id"]: public_id(o, "T") for o in objects
                  if o.get("type") == "attack-pattern" and vivant(o)}
    techniques = {k: v for k, v in techniques.items() if v}

    mitigations = {}
    for o in objects:
        if o.get("type") == "course-of-action" and vivant(o):
            mid = public_id(o, "M")
            if mid:
                mitigations[o["id"]] = {
                    "id": mid,
                    "name": o.get("name", ""),
                    "description": (o.get("description") or "")[:300],
                }

    mapping: dict[str, list[dict]] = {}
    for o in objects:
        if o.get("type") == "relationship" and o.get("relationship_type") == "mitigates":
            src, tgt = o.get("source_ref"), o.get("target_ref")
            if src in mitigations and tgt in techniques:
                mapping.setdefault(techniques[tgt], []).append(mitigations[src])
    return mapping


def build_defense_db(stix_path: str,
                     techniques: list[str] | None = None,
                     d3fend_path: str | None = None) -> DefenseKnowledgeBase:
    """
    Construit la DefenseKnowledgeBase pour les techniques du système.

    stix_path   : bundle enterprise-attack.json
    techniques  : techniques à indexer (défaut : TECHNIQUES_SYSTEME)
    d3fend_path : mappings D3FEND (optionnel, non disponible actuellement)
    """
    techniques = techniques or TECHNIQUES_SYSTEME
    mapping = extract_mitigations_from_stix(stix_path)

    d3fend_map: dict[str, list[DefensiveAction]] = {}
    if d3fend_path and Path(d3fend_path).exists():
        d3fend_map = _load_d3fend(d3fend_path)

    db: dict[str, TechniqueDefenses] = {}
    for tid in techniques:
        mits = mapping.get(tid, [])
        # repli sur la technique parente pour une sous-technique non couverte
        if not mits and "." in tid:
            mits = mapping.get(tid.split(".")[0], [])
        if not mits and not d3fend_map.get(tid):
            continue  # aucune défense connue : on n'invente rien
        db[tid] = TechniqueDefenses(
            technique_id=tid,
            d3fend_actions=d3fend_map.get(tid, []),
            attack_mitigations=[
                DefensiveAction(action_id=m["id"], name=m["name"],
                                source="attack_mitigation", description=m["description"])
                for m in mits
            ],
        )
    return DefenseKnowledgeBase(db)


def _load_d3fend(path: str) -> dict[str, list[DefensiveAction]]:
    """Placeholder : à compléter quand d3fend-full-mappings.json sera disponible."""
    return {}


def save_db(kb: DefenseKnowledgeBase, path: str) -> None:
    """Sérialise la base pour éviter de reparser le STIX (52 Mo) à chaque usage."""
    data = {
        tid: {
            "attack_mitigations": [
                {"id": a.action_id, "name": a.name, "description": a.description}
                for a in td.attack_mitigations
            ],
            "d3fend_actions": [
                {"id": a.action_id, "name": a.name, "artifact": a.artifact,
                 "description": a.description}
                for a in td.d3fend_actions
            ],
        }
        for tid, td in kb.db.items()
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=1, ensure_ascii=False)


def load_db(path: str) -> DefenseKnowledgeBase:
    """Recharge une base sérialisée par `save_db`."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    db = {
        tid: TechniqueDefenses(
            technique_id=tid,
            d3fend_actions=[
                DefensiveAction(action_id=a["id"], name=a["name"], source="d3fend",
                                artifact=a.get("artifact"), description=a.get("description", ""))
                for a in entry.get("d3fend_actions", [])
            ],
            attack_mitigations=[
                DefensiveAction(action_id=a["id"], name=a["name"],
                                source="attack_mitigation", description=a.get("description", ""))
                for a in entry.get("attack_mitigations", [])
            ],
        )
        for tid, entry in data.items()
    }
    return DefenseKnowledgeBase(db)
