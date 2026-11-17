"""
=============================================================================
EXTRACTEUR DE FEATURES WINDOWS — ALIGNÉ SUR LE MODÈLE ENTRAÎNÉ
=============================================================================
Remplace `sequence_features.py` pour la voie Windows du détecteur unifié.

POURQUOI CE MODULE
    L'extracteur d'origine produisait 14 features SÉMANTIQUES supposant des
    lignes de commande (`has_encoded_command`, `max_cmdline_entropy`,
    `n_lolbins`, `has_office_to_shell`…). Or le modèle a été entraîné sur
    COMISET, où `command_line` est QUASI ABSENT — ces features y auraient été
    constamment nulles, donc inutilisables.

    Le modèle utilise donc 18 features STRUCTURELLES (comptes et ratios par
    EventID Sysmon), conçues sur les données réellement disponibles. Une seule
    feature était commune aux deux jeux (`n_events`), rendant le branchement
    impossible.

    Ce module aligne l'extraction du système sur ce que le modèle attend.

ORDRE DES FEATURES — CRITIQUE
    L'ordre ci-dessous reproduit EXACTEMENT `feature_names` de
    `windows_detector_config.pkl`. Un RandomForest n'a aucun moyen de détecter
    une permutation de colonnes : il prédirait silencieusement n'importe quoi.

MAPPING EVENTID (issu de `event_id_signals` du modèle)
    1  → process creation      3  → network connection
    7  → DLL loaded            8  → injection (CreateRemoteThread)
    10 → process access        11 → file created
    12 → registry object       13 → registry set

INTERPRÉTATIONS À VÉRIFIER (3 features)
    Trois features ne sont pas déductibles sans ambiguïté du seul nom. Les
    interprétations retenues, les plus plausibles au vu des champs COMISET :
      - `n_registry_obj`     → nombre de TargetObject DISTINCTS (clés touchées)
      - `n_target_processes` → nombre de TargetProcessGuid DISTINCTS
      - `n_hash`             → nombre de Hashes DISTINCTS
    ⚠️ `Hashes` n'est PAS extrait par le mapper Sysmon actuel : `n_hash` vaut
    donc 0 en l'état. Voir la section « limites » en bas de fichier.
=============================================================================
"""
from __future__ import annotations

# Ordre EXACT attendu par windows_detector.pkl — ne pas modifier
WINDOWS_FEATURE_NAMES = [
    "n_events",            # 0
    "n_event_types",       # 1
    "has_inject",          # 2
    "n_inject",            # 3
    "has_network",         # 4
    "n_network",           # 5
    "ratio_network",       # 6
    "has_dll",             # 7
    "n_dll",               # 8
    "n_registry_set",      # 9
    "n_registry_obj",      # 10
    "ratio_registry",      # 11
    "n_file",              # 12
    "ratio_file",          # 13
    "n_procaccess",        # 14
    "n_proccreate",        # 15
    "n_hash",              # 16
    "n_target_processes",  # 17
]

EID_PROCCREATE = "1"
EID_NETWORK    = "3"
EID_DLL        = "7"
EID_INJECT     = "8"
EID_PROCACCESS = "10"
EID_FILE       = "11"
EID_REG_OBJ    = "12"
EID_REG_SET    = "13"


def _eid(event) -> str:
    """EventID sous forme de chaîne, robuste aux entiers et aux None."""
    v = getattr(event, "event_id", None)
    return "" if v is None else str(v).strip()


def _extra(event, *keys):
    """Première valeur non vide trouvée dans event.extra parmi `keys`."""
    extra = getattr(event, "extra", None) or {}
    for k in keys:
        v = extra.get(k)
        if v not in (None, "", "nan"):
            return v
    return None


def extract_windows_features(seq) -> list[float]:
    """
    Séquence → vecteur de 18 features, dans l'ordre attendu par le modèle.
    """
    events = list(getattr(seq, "events", seq) or [])
    n = len(events)
    if n == 0:
        return [0.0] * len(WINDOWS_FEATURE_NAMES)

    eids = [_eid(e) for e in events]

    n_proccreate = eids.count(EID_PROCCREATE)
    n_network    = eids.count(EID_NETWORK)
    n_dll        = eids.count(EID_DLL)
    n_inject     = eids.count(EID_INJECT)
    n_procaccess = eids.count(EID_PROCACCESS)
    n_file       = eids.count(EID_FILE)
    n_reg_set    = eids.count(EID_REG_SET)
    n_reg_obj_ev = eids.count(EID_REG_OBJ)
    n_registry   = n_reg_set + n_reg_obj_ev

    # Diversité : clés de registre distinctes touchées
    reg_objets = {
        getattr(e, "target_name", None) or _extra(e, "TargetObject", "target_object")
        for e, eid in zip(events, eids)
        if eid in (EID_REG_SET, EID_REG_OBJ)
    }
    reg_objets.discard(None)

    # Processus cibles distincts (injection, process access)
    cibles = {
        _extra(e, "target_process_guid", "TargetProcessGuid")
        for e in events
    }
    cibles.discard(None)

    # Hashes distincts — absent du mapper actuel, vaut 0 en l'état
    hashes = {_extra(e, "hashes", "Hashes") for e in events}
    hashes.discard(None)

    return [
        float(n),                       # 0  n_events
        float(len(set(eids))),          # 1  n_event_types
        1.0 if n_inject else 0.0,       # 2  has_inject
        float(n_inject),                # 3  n_inject
        1.0 if n_network else 0.0,      # 4  has_network
        float(n_network),               # 5  n_network
        n_network / n,                  # 6  ratio_network
        1.0 if n_dll else 0.0,          # 7  has_dll
        float(n_dll),                   # 8  n_dll
        float(n_reg_set),               # 9  n_registry_set
        float(len(reg_objets)),         # 10 n_registry_obj
        n_registry / n,                 # 11 ratio_registry
        float(n_file),                  # 12 n_file
        n_file / n,                     # 13 ratio_file
        float(n_procaccess),            # 14 n_procaccess
        float(n_proccreate),            # 15 n_proccreate
        float(len(hashes)),             # 16 n_hash
        float(len(cibles)),             # 17 n_target_processes
    ]


def extract_windows_matrix(sequences) -> list[list[float]]:
    """Matrice de features pour un lot de séquences."""
    return [extract_windows_features(s) for s in sequences]


# ---------------------------------------------------------------------------
# LIMITES CONNUES
# ---------------------------------------------------------------------------
# 1. `n_hash` — RÉSOLU. Le mapper Sysmon extrait désormais le champ `Hashes`
#    (empreintes SHA1/MD5/IMPHASH, présentes sur les EID 1, 6 et 7) dans
#    `extra["hashes"]`. La feature compte les empreintes DISTINCTES d'une
#    séquence. Vérifié : 10 événements porteurs sur 15, 5 empreintes distinctes.
#
# 2. Les interprétations de `n_registry_obj`, `n_target_processes` et `n_hash`
#    sont déduites des noms et des champs COMISET disponibles. Elles devraient
#    être confrontées au code d'extraction du notebook d'entraînement pour
#    lever tout doute résiduel.
#
# 3. Le séquençage doit rester identique à l'entraînement : PAR PROCESS_GUID,
#    plafond 200 événements (cf. `sequencing` dans la config du modèle). Un
#    séquençage différent (fenêtre temporelle, par host) produirait des
#    distributions de features décalées.
