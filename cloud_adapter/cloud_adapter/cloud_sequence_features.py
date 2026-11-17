# =============================================================================
# FEATURES CLOUD (CloudTrail) — pour le détecteur Analysis unifié
# =============================================================================
# Équivalent cloud de sequence_features.py (Windows). Extrait un vecteur de
# features COMPORTEMENTALES d'une séquence d'événements CloudTrail, structuré
# selon les tactiques MITRE ATT&CK Cloud Matrix.
#
# ANCRAGE ÉTAT DE L'ART (voir ETAT_ART_FEATURES_CLOUD.md) :
#   - profilage par IDENTITÉ (séquence = actions d'un principal)
#   - familles de features prouvées : volume/vélocité, rareté, erreurs,
#     diversité de services
#   - structuration par tactiques MITRE (recon, credential access, escalade,
#     persistance, évasion défensive, impact)
#
# ANCRAGE DONNÉES RÉELLES (dataset Invictus, vérifié) : tous les champs utilisés
# (eventName via process_name, eventSource via cloud_service, errorCode via
# outcome, userIdentity) existent dans les vraies données CloudTrail.
#
# PARALLÈLE avec les features Windows (défendable en thèse) :
#   Windows has_office_to_shell   ~  Cloud has_privilege_escalation
#   Windows n_lolbins             ~  Cloud n_recon_calls
#   Windows has_encoded_command   ~  Cloud has_defense_evasion
#   Windows has_external_network  ~  Cloud has_exfiltration
#   Windows has_integrity_flags   ~  Cloud has_integrity_flag
# =============================================================================

from __future__ import annotations

# --- Catalogues d'actions CloudTrail par tactique MITRE (extensibles) --------
# Reconnaissance : découverte de l'environnement (List*, Describe*, Get*Identity)
RECON_ACTIONS = {
    "GetCallerIdentity", "DescribeInstances", "DescribeNatGateways",
    "ListBuckets", "ListUsers", "ListRoles", "ListSecrets", "DescribeSecret",
    "DescribeParameters", "ListTagsForResource", "GetAccountSummary",
    "DescribeInstanceInformation", "ListAccessKeys", "GetResourcePolicy",
}
# préfixes de reconnaissance (capture les nombreuses variantes Describe*/List*)
RECON_PREFIXES = ("Describe", "List", "Get")

# Credential Access : vol de secrets/identifiants
CREDENTIAL_ACTIONS = {
    "GetSecretValue", "GetPasswordData", "GetParameter", "GetParameters",
    "Decrypt", "GenerateDataKey", "RetrieveSecretValue", "GetLoginProfile",
}

# Privilege Escalation : élévation de droits
PRIV_ESCALATION_ACTIONS = {
    "AttachUserPolicy", "PutUserPolicy", "AttachRolePolicy", "PutRolePolicy",
    "CreatePolicyVersion", "SetDefaultPolicyVersion", "AddUserToGroup",
    "UpdateAssumeRolePolicy", "CreateLoginProfile", "UpdateLoginProfile",
}

# Persistence : maintien d'accès
PERSISTENCE_ACTIONS = {
    "CreateUser", "CreateRole", "CreateAccessKey", "CreateLoginProfile",
    "CreateSecret", "PutSecretValue", "PutParameter", "ImportKeyPair",
    "CreateServiceSpecificCredential",
}

# Defense Evasion : effacement/désactivation des défenses (très discriminant)
DEFENSE_EVASION_ACTIONS = {
    "StopLogging", "DeleteTrail", "UpdateTrail", "DeleteFlowLogs",
    "DeleteDetector", "DisassociateFromMasterAccount", "DeleteConfigRule",
    "StopConfigurationRecorder", "DeleteLogGroup", "PutEventSelectors",
}

# Impact / Exfiltration : vol ou destruction
IMPACT_ACTIONS = {
    "DeleteObject", "DeleteBucket", "DeleteDBInstance", "ModifySnapshotAttribute",
    "PutBucketPolicy", "PutBucketAcl", "SharedSnapshot", "CreateSnapshot",
    "PutBucketVersioning", "DeleteSnapshot", "CopySnapshot",
}

# Codes/états d'erreur signalant un tâtonnement de l'attaquant
ERROR_OUTCOMES = {"AccessDenied", "UnauthorizedOperation",
                  "Client.UnauthorizedOperation", "Forbidden", "failure", "error"}


FEATURE_NAMES = [
    # --- volume & vélocité ---
    "n_events", "event_velocity", "duration_seconds",
    # --- diversité (un attaquant balaie large) ---
    "n_distinct_services", "n_distinct_actions",
    # --- reconnaissance ---
    "n_recon_calls", "recon_ratio",
    # --- erreurs (tâtonnement) ---
    "n_errors", "error_ratio",
    # --- lecture vs écriture ---
    "write_ratio",
    # --- signaux tactiques MITRE (binaires, très discriminants) ---
    "has_credential_access", "n_credential_calls",
    "has_privilege_escalation",
    "has_persistence",
    "has_defense_evasion",
    "has_impact",
    # --- intégrité (annotation du Collect) ---
    "has_integrity_flag",
]


def _action_of(event) -> str:
    """L'action API de l'événement (portée par process_name côté canonique cloud)."""
    return (getattr(event, "process_name", None) or "").strip()


def _service_of(event) -> str:
    extra = getattr(event, "extra", None) or {}
    return extra.get("cloud_service") or ""


def _outcome_of(event) -> str:
    extra = getattr(event, "extra", None) or {}
    return str(extra.get("outcome") or "")


def _is_recon(action: str) -> bool:
    if action in RECON_ACTIONS:
        return True
    return action.startswith(RECON_PREFIXES)


def _is_write(action: str) -> bool:
    """Action de modification (heuristique : pas un Get/List/Describe)."""
    return not action.startswith(("Get", "List", "Describe"))


def extract_cloud_features(seq) -> list[float]:
    """
    Extrait le vecteur de features d'une séquence d'événements CloudTrail.
    seq : objet Sequence (avec .events, .duration_seconds, .integrity_flags()).
    Retourne une liste de floats dans l'ordre de FEATURE_NAMES.
    """
    events = list(getattr(seq, "events", []))
    n = len(events)
    if n == 0:
        return [0.0] * len(FEATURE_NAMES)

    actions = [_action_of(e) for e in events]
    services = [_service_of(e) for e in events]
    outcomes = [_outcome_of(e) for e in events]

    # volume & vélocité
    duration = float(getattr(seq, "duration_seconds", 0.0) or 0.0)
    velocity = n / duration if duration > 0 else float(n)  # événements/seconde

    # diversité
    n_services = len(set(s for s in services if s))
    n_actions = len(set(a for a in actions if a))

    # reconnaissance
    n_recon = sum(1 for a in actions if _is_recon(a))
    recon_ratio = n_recon / n

    # erreurs (tâtonnement)
    n_errors = sum(1 for o in outcomes if o in ERROR_OUTCOMES)
    error_ratio = n_errors / n

    # lecture vs écriture
    n_write = sum(1 for a in actions if _is_write(a))
    write_ratio = n_write / n

    # signaux tactiques MITRE
    action_set = set(actions)
    n_credential = sum(1 for a in actions if a in CREDENTIAL_ACTIONS)
    has_credential = 1.0 if n_credential > 0 else 0.0
    has_priv_esc = 1.0 if action_set & PRIV_ESCALATION_ACTIONS else 0.0
    has_persistence = 1.0 if action_set & PERSISTENCE_ACTIONS else 0.0
    has_evasion = 1.0 if action_set & DEFENSE_EVASION_ACTIONS else 0.0
    has_impact = 1.0 if action_set & IMPACT_ACTIONS else 0.0

    # intégrité
    integ = getattr(seq, "integrity_flags", None)
    has_integrity = 1.0 if (callable(integ) and integ()) else 0.0

    return [
        float(n), float(velocity), duration,
        float(n_services), float(n_actions),
        float(n_recon), recon_ratio,
        float(n_errors), error_ratio,
        write_ratio,
        has_credential, float(n_credential),
        has_priv_esc,
        has_persistence,
        has_evasion,
        has_impact,
        has_integrity,
    ]


def extract_cloud_matrix(sequences) -> list[list[float]]:
    """Extrait la matrice de features pour une liste de séquences."""
    return [extract_cloud_features(s) for s in sequences]
