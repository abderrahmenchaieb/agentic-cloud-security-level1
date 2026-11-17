# =============================================================================
# SCHÉMA CANONIQUE — Collect Agent
# =============================================================================
# Structure pivot vers laquelle TOUTES les sources sont normalisées.
# Conçu pour être AGNOSTIQUE DE LA SOURCE :
#   - aujourd'hui  : logs Windows/Sysmon des VMs
#   - demain       : plan de contrôle cloud (CloudTrail / Azure Activity / GCP)
#
# Inspiré des standards OCSF et ECS, simplifié pour le périmètre de la thèse.
# La règle : un agent en aval (Analysis, Geolocation) ne doit JAMAIS avoir
# besoin de connaître la source d'origine — il lit uniquement le canonique.
# =============================================================================

from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Any
from pydantic import BaseModel, Field, field_validator
import uuid


# -----------------------------------------------------------------------------
# 1. ÉNUMÉRATIONS — vocabulaire contrôlé (extensible)
# -----------------------------------------------------------------------------

class SourceType(str, Enum):
    """Grande famille de la source. Extensible sans casser l'aval."""
    ENDPOINT = "endpoint"          # VM/hôte : Sysmon, WEL, auditd
    CLOUD_CONTROL = "cloud_control"  # plan de contrôle : CloudTrail, Azure Activity, GCP Audit
    NETWORK = "network"            # équipements réseau, flux
    APPLICATION = "application"     # logs applicatifs


class ActivityCategory(str, Enum):
    """
    Catégorie d'activité — NORMALISÉE et commune à toutes les sources.
    C'est le pont sémantique : un 'ProcessCreate' Sysmon et un 'RunInstances'
    CloudTrail sont deux façons de 'créer une ressource de calcul'.
    """
    PROCESS = "process"            # création/arrêt de processus (Sysmon EID 1), lancement de calcul cloud
    NETWORK_CONNECTION = "network_connection"  # connexion (Sysmon EID 3), flux
    AUTHENTICATION = "authentication"  # logon (4624/4625), AssumeRole cloud
    FILE = "file"                  # création/modif fichier (Sysmon EID 11), objet stockage cloud
    REGISTRY = "registry"          # registre Windows (Sysmon EID 12/13)
    MODULE_LOAD = "module_load"    # chargement DLL (Sysmon EID 7)
    PROCESS_ACCESS = "process_access"  # accès mémoire inter-processus (Sysmon EID 8/10) — injection
    CONFIG_CHANGE = "config_change"  # modif de configuration (surtout cloud : IAM, security group)
    RESOURCE_MANAGEMENT = "resource_management"  # création/suppression de ressource cloud
    OTHER = "other"


class Outcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


# -----------------------------------------------------------------------------
# 2. BLOCS RÉUTILISABLES
# -----------------------------------------------------------------------------

class Actor(BaseModel):
    """QUI a fait l'action. Rempli différemment selon la source, même structure."""
    user_id: Optional[str] = None        # SID Windows, ARN/principal cloud
    user_name: Optional[str] = None
    session_id: Optional[str] = None     # logon ID Windows, session cloud
    # IP source — TOUJOURS préservée quand elle existe (matière première Geolocation)
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None     # utile côté cloud (SDK/console)
    # Cloud-spécifique (None pour endpoint) :
    account_id: Optional[str] = None     # compte AWS/Azure/GCP
    principal_type: Optional[str] = None  # IAMUser, AssumedRole, Service...


class ProcessContext(BaseModel):
    """
    Contexte processus — CRUCIAL pour l'Analysis Agent (séquences).
    Le process_guid (Sysmon) est l'identifiant unique et STABLE pour
    reconstruire l'arbre de processus. Côté cloud, ces champs sont None.
    """
    process_guid: Optional[str] = None   # Sysmon ProcessGuid — clé de corrélation
    process_id: Optional[int] = None     # PID (réutilisable — ne pas utiliser seul)
    process_name: Optional[str] = None
    command_line: Optional[str] = None   # essentiel : encodage, obfuscation
    parent_process_guid: Optional[str] = None  # → filiation fiable
    parent_process_id: Optional[int] = None
    parent_process_name: Optional[str] = None
    integrity_level: Optional[str] = None


class Target(BaseModel):
    """SUR QUOI porte l'action (ressource ciblée)."""
    type: Optional[str] = None           # "process", "file", "registry_key", "s3_bucket", "iam_role"...
    name: Optional[str] = None
    id: Optional[str] = None
    # Réseau (si applicable) :
    destination_ip: Optional[str] = None  # préservée pour Geolocation
    destination_port: Optional[int] = None
    protocol: Optional[str] = None


class CloudContext(BaseModel):
    """
    Contexte spécifique au plan de contrôle cloud. None pour les endpoints.
    Présent dès maintenant dans le schéma pour ne PAS avoir à le retrofitter
    quand on ajoutera la couche cloud (Phase 2).
    """
    provider: Optional[str] = None       # "aws" | "azure" | "gcp"
    region: Optional[str] = None
    service: Optional[str] = None        # "ec2", "s3", "iam"...
    api_call: Optional[str] = None       # "RunInstances", "PutObject", "AssumeRole"...
    resource_arn: Optional[str] = None


# -----------------------------------------------------------------------------
# 3. LE LOG CANONIQUE
# -----------------------------------------------------------------------------

class CanonicalLog(BaseModel):
    """
    Un événement normalisé. Toute source y est mappée.
    Les agents en aval ne lisent QUE cette structure.
    """
    # --- Identité & provenance ---
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    schema_version: str = "1.0"
    source_type: SourceType
    source_provider: str                 # "sysmon", "windows_security", "aws_cloudtrail"...

    # --- Temps ---
    event_time: datetime                 # quand l'événement s'est produit (source)
    ingest_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # --- Sémantique normalisée ---
    activity: ActivityCategory
    action_name: str                     # nom brut de l'action ("ProcessCreate", "RunInstances")
    outcome: Outcome = Outcome.UNKNOWN

    # --- Acteurs & cibles (blocs communs) ---
    actor: Actor = Field(default_factory=Actor)
    target: Target = Field(default_factory=Target)

    # --- Contextes spécifiques (l'un OU l'autre selon la source) ---
    process_context: Optional[ProcessContext] = None   # endpoints
    cloud_context: Optional[CloudContext] = None        # cloud

    # --- Traçabilité & extension ---
    host: Optional[str] = None           # nom de la VM / hôte
    raw_ref: Optional[str] = None        # pointeur vers le log brut (pas le brut entier)
    extra: dict[str, Any] = Field(default_factory=dict)  # extension sans casser le schéma

    # --- Validation ---
    @field_validator("event_time", "ingest_time")
    @classmethod
    def ensure_tz(cls, v: datetime) -> datetime:
        """Force l'UTC — indispensable pour corréler des sources hétérogènes."""
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)

    def clock_skew_seconds(self) -> float:
        """Écart event_time / ingest_time — feature utile (détection d'anomalie)."""
        return abs((self.ingest_time - self.event_time).total_seconds())


# -----------------------------------------------------------------------------
# 4. RÉSULTAT DE VALIDATION (pour séparer valides / malformés)
# -----------------------------------------------------------------------------

class ValidationResult(BaseModel):
    is_valid: bool
    log: Optional[CanonicalLog] = None
    rejection_reason: Optional[str] = None
    raw: Optional[dict] = None
