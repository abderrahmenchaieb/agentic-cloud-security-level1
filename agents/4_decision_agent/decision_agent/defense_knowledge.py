# =============================================================================
# BASE DE CONNAISSANCES DES DÉFENSES (D3FEND + ATT&CK Mitigations)
# =============================================================================
# Fournit, pour une technique MITRE détectée, les actions défensives candidates.
# Deux sources, en cascade (comme lookup→GNN ailleurs) :
#   1. D3FEND (précis) : technique → artefacts → contre-mesures défensives
#   2. ATT&CK Mitigations (filet, couverture large) : technique → mitigations
#
# Raffinement "niveau artefacts" : on privilégie les défenses D3FEND qui
# opèrent sur les artefacts RÉELLEMENT observés (fournis par l'Analysis Agent),
# pas sur la technique abstraite.
#
# NOTE : ici, échantillon d'exemple. En production, charger :
#   - d3fend-full-mappings.json (D3FEND, téléchargé et stocké en local)
#   - les mitigations ATT&CK (déjà dans mitre_matrix.json)
# via load_d3fend() / load_attack_mitigations() à adapter au format réel.
# =============================================================================

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DefensiveAction:
    """Une action défensive candidate."""
    action_id: str                  # ex "D3-NTA" (D3FEND) ou "M1042" (ATT&CK)
    name: str
    source: str                     # "d3fend" | "attack_mitigation"
    artifact: Optional[str] = None  # artefact D3FEND sur lequel elle opère
    description: str = ""
    # techniques détectées que cette action couvre (rempli par candidate_actions) :
    # une action couvrant plusieurs techniques est prioritaire
    covers: list = field(default_factory=list)


@dataclass
class TechniqueDefenses:
    """Défenses associées à une technique MITRE."""
    technique_id: str
    d3fend_actions: list[DefensiveAction] = field(default_factory=list)
    attack_mitigations: list[DefensiveAction] = field(default_factory=list)


# Mapping des catégories d'artefacts (Analysis Agent) → artefacts D3FEND
# (le Decision Agent porte cette connaissance, pas l'Analysis Agent)
ARTIFACT_TO_D3FEND = {
    "network_traffic": "d3f:NetworkTraffic",
    "file": "d3f:File",
    "registry_key": "d3f:WindowsRegistryKey",
    "process": "d3f:Process",
    "process_access": "d3f:Process",
    "module_load": "d3f:Module",
    "authentication": "d3f:UserAccount",
}


# -----------------------------------------------------------------------------
# Échantillon de base D3FEND + ATT&CK (à remplacer par les fichiers réels)
# -----------------------------------------------------------------------------
SAMPLE_DEFENSE_DB: dict[str, TechniqueDefenses] = {
    "T1059.001": TechniqueDefenses(  # PowerShell
        technique_id="T1059.001",
        d3fend_actions=[
            DefensiveAction("D3-SCA", "Script Execution Analysis", "d3fend",
                            artifact="d3f:Process",
                            description="Analyser l'exécution des scripts pour détecter le code malveillant."),
            DefensiveAction("D3-PSEP", "Process Spawn Analysis", "d3fend",
                            artifact="d3f:Process",
                            description="Analyser les processus enfants anormaux."),
            DefensiveAction("D3-NTA", "Network Traffic Analysis", "d3fend",
                            artifact="d3f:NetworkTraffic",
                            description="Inspecter le trafic réseau généré par le processus."),
        ],
        attack_mitigations=[
            DefensiveAction("M1042", "Disable or Remove Feature or Program", "attack_mitigation",
                            description="Restreindre/désactiver PowerShell si non nécessaire."),
            DefensiveAction("M1038", "Execution Prevention", "attack_mitigation",
                            description="Application control pour bloquer l'exécution non autorisée."),
        ],
    ),
    "T1071.001": TechniqueDefenses(  # Web Protocols (C2)
        technique_id="T1071.001",
        d3fend_actions=[
            DefensiveAction("D3-NTA", "Network Traffic Analysis", "d3fend",
                            artifact="d3f:NetworkTraffic",
                            description="Analyser le trafic web pour détecter le C2."),
            DefensiveAction("D3-OTF", "Outbound Traffic Filtering", "d3fend",
                            artifact="d3f:NetworkTraffic",
                            description="Filtrer/bloquer le trafic sortant vers l'hôte suspect."),
        ],
        attack_mitigations=[
            DefensiveAction("M1031", "Network Intrusion Prevention", "attack_mitigation",
                            description="IPS pour détecter/bloquer les communications C2."),
        ],
    ),
    "T1033": TechniqueDefenses(  # System Owner/User Discovery
        technique_id="T1033",
        d3fend_actions=[
            DefensiveAction("D3-PSA", "Process Self-Modification Analysis", "d3fend",
                            artifact="d3f:Process",
                            description="Surveiller les commandes de reconnaissance système."),
        ],
        attack_mitigations=[],  # ATT&CK note : peu de mitigation directe (discovery)
    ),
    "T1069.002": TechniqueDefenses(  # Domain Groups
        technique_id="T1069.002",
        d3fend_actions=[
            DefensiveAction("D3-UAA", "User Account Analysis", "d3fend",
                            artifact="d3f:UserAccount",
                            description="Surveiller l'énumération des groupes de domaine."),
        ],
        attack_mitigations=[],
    ),
    "T1036.005": TechniqueDefenses(  # Masquerading
        technique_id="T1036.005",
        d3fend_actions=[
            DefensiveAction("D3-FCA", "File Content Analysis", "d3fend",
                            artifact="d3f:File",
                            description="Vérifier la légitimité des exécutables masqués."),
            DefensiveAction("D3-PSEP", "Process Spawn Analysis", "d3fend",
                            artifact="d3f:Process",
                            description="Détecter les processus au nom usurpé."),
        ],
        attack_mitigations=[
            DefensiveAction("M1045", "Code Signing", "attack_mitigation",
                            description="Exiger la signature de code pour bloquer les binaires usurpés."),
        ],
    ),
}


class DefenseKnowledgeBase:
    """Fournit les défenses candidates pour une technique, avec raffinement artefacts."""

    def __init__(self, db: Optional[dict] = None):
        self.db = db if db is not None else SAMPLE_DEFENSE_DB

    def get_defenses(self, technique_id: str) -> Optional[TechniqueDefenses]:
        return self.db.get(technique_id)

    def candidate_actions(self, technique_ids: list[str],
                          observed_artifacts: Optional[list[str]] = None
                          ) -> list[DefensiveAction]:
        """
        Rassemble les actions candidates pour un ensemble de techniques.
        Si observed_artifacts est fourni → RAFFINEMENT : on privilégie les
        défenses D3FEND qui opèrent sur les artefacts réellement observés.
        """
        # artefacts D3FEND correspondant aux observations
        observed_d3fend = None
        if observed_artifacts:
            observed_d3fend = {ARTIFACT_TO_D3FEND.get(a) for a in observed_artifacts}
            observed_d3fend.discard(None)

        actions: list[DefensiveAction] = []
        seen_ids: set[str] = set()
        coverage: dict[str, list[str]] = {}

        for tid in technique_ids:
            defenses = self.db.get(tid)
            if not defenses:
                continue

            # D3FEND en priorité, filtré/priorisé par artefacts observés
            for a in defenses.d3fend_actions:
                if observed_d3fend is not None and a.artifact:
                    # niveau artefacts : ne garder que les défenses dont l'artefact
                    # a été RÉELLEMENT observé
                    if a.artifact not in observed_d3fend:
                        continue
                # dédoublonnage GLOBAL (et non par technique) : une même action
                # couvrant plusieurs techniques détectées ne doit être proposée
                # qu'une fois à l'utilisateur. Les techniques couvertes sont
                # tracées dans `covers` pour permettre la priorisation.
                if a.action_id not in seen_ids:
                    actions.append(a)
                    seen_ids.add(a.action_id)
                    coverage[a.action_id] = [tid]
                else:
                    coverage.setdefault(a.action_id, []).append(tid)

            # ATT&CK mitigations en filet (toujours ajoutées)
            for m in defenses.attack_mitigations:
                if m.action_id not in seen_ids:
                    actions.append(m)
                    seen_ids.add(m.action_id)
                    coverage[m.action_id] = [tid]
                else:
                    coverage.setdefault(m.action_id, []).append(tid)

        # une action qui mitige PLUSIEURS techniques détectées est prioritaire
        actions.sort(key=lambda a: -len(coverage.get(a.action_id, [])))
        for a in actions:
            a.covers = coverage.get(a.action_id, [])

        return actions
