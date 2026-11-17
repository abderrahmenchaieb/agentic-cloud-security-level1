# =============================================================================
# ADAPTATEUR CLOUD — traduit les logs de contrôle cloud vers le schéma canonique
# =============================================================================
# Rend le système "adaptatif à n'importe quel cloud" par le pattern ADAPTATEUR :
#   un adaptateur PAR cloud, qui traduit son format natif vers le schéma
#   canonique. Le reste du système (les 4 agents) ne change JAMAIS — il ne voit
#   que du canonique. Ajouter un cloud = ajouter un adaptateur.
#
#   AWS CloudTrail  ──┐
#   Azure Activity  ──┼──► ADAPTATEUR (par cloud) ──► CanonicalLog ──► Collect Agent
#   GCP Audit Logs  ──┘
#
# Ce module fournit :
#   - CloudAdapter        : interface commune (contrat de tout adaptateur)
#   - AwsCloudTrailAdapter: implémentation AWS CloudTrail (format Records[])
#   - le mapping eventName → ActivityCategory (pont sémantique)
#   - la clé de corrélation cloud : userIdentity/session (remplace ProcessGUID)
#
# Format CloudTrail vérifié sur la doc AWS officielle : array Records[], champs
# eventTime, eventSource, eventName, userIdentity, sourceIPAddress, awsRegion,
# userAgent, requestParameters, errorCode, eventID.
# =============================================================================

from __future__ import annotations
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Optional, Iterator
import json
import gzip

from collect_agent.canonical_schema import (
    CanonicalLog, SourceType, ActivityCategory, Outcome,
    Actor, Target, CloudContext,
)


# -----------------------------------------------------------------------------
# Interface commune : tout adaptateur cloud implémente ce contrat
# -----------------------------------------------------------------------------
class CloudAdapter(ABC):
    """Contrat commun à tous les adaptateurs cloud."""

    provider: str = "unknown"

    @abstractmethod
    def parse(self, raw_content: str) -> list[CanonicalLog]:
        """Traduit le contenu brut d'un cloud vers une liste de CanonicalLog."""
        ...

    @abstractmethod
    def map_activity(self, native_event: dict) -> ActivityCategory:
        """Mappe un événement natif vers la catégorie d'activité canonique."""
        ...


# -----------------------------------------------------------------------------
# AWS CloudTrail
# -----------------------------------------------------------------------------

# Mapping eventName CloudTrail → ActivityCategory canonique.
# (le pont sémantique : "RunInstances" cloud ≈ "création de calcul")
# On mappe par PRÉFIXE d'action ; peaufinable, non exhaustif (filet: OTHER).
_ACTION_PREFIX_MAP = {
    # authentification / identité
    "AssumeRole": ActivityCategory.AUTHENTICATION,
    "ConsoleLogin": ActivityCategory.AUTHENTICATION,
    "GetSessionToken": ActivityCategory.AUTHENTICATION,
    "GetFederationToken": ActivityCategory.AUTHENTICATION,
    # gestion de ressources de calcul
    "RunInstances": ActivityCategory.RESOURCE_MANAGEMENT,
    "StartInstances": ActivityCategory.RESOURCE_MANAGEMENT,
    "StopInstances": ActivityCategory.RESOURCE_MANAGEMENT,
    "TerminateInstances": ActivityCategory.RESOURCE_MANAGEMENT,
    "CreateFunction": ActivityCategory.RESOURCE_MANAGEMENT,
    # stockage (objets = équivalent "fichier")
    "PutObject": ActivityCategory.FILE,
    "GetObject": ActivityCategory.FILE,
    "DeleteObject": ActivityCategory.FILE,
    "ListObjects": ActivityCategory.FILE,
    # changement de configuration / IAM (surface d'attaque cloud majeure)
    "PutUserPolicy": ActivityCategory.CONFIG_CHANGE,
    "AttachUserPolicy": ActivityCategory.CONFIG_CHANGE,
    "AttachRolePolicy": ActivityCategory.CONFIG_CHANGE,
    "CreateUser": ActivityCategory.CONFIG_CHANGE,
    "CreateAccessKey": ActivityCategory.CONFIG_CHANGE,
    "CreateRole": ActivityCategory.CONFIG_CHANGE,
    "PutBucketPolicy": ActivityCategory.CONFIG_CHANGE,
    "AuthorizeSecurityGroupIngress": ActivityCategory.CONFIG_CHANGE,
    "ModifyInstanceAttribute": ActivityCategory.CONFIG_CHANGE,
    # manipulation du logging (défense évasion — surveillé par le Collect Agent)
    "StopLogging": ActivityCategory.CONFIG_CHANGE,
    "DeleteTrail": ActivityCategory.CONFIG_CHANGE,
    "UpdateTrail": ActivityCategory.CONFIG_CHANGE,
    "PutEventSelectors": ActivityCategory.CONFIG_CHANGE,
    # reconnaissance / lecture (discovery)
    "ListUsers": ActivityCategory.OTHER,
    "ListRoles": ActivityCategory.OTHER,
    "GetCallerIdentity": ActivityCategory.OTHER,
    "DescribeInstances": ActivityCategory.OTHER,
    "ListBuckets": ActivityCategory.OTHER,
}


class AwsCloudTrailAdapter(CloudAdapter):
    """
    Adaptateur AWS CloudTrail.
    Lit le format classique (array Records[]), gzip ou JSON brut, et traduit
    chaque événement vers un CanonicalLog.
    """

    provider = "aws"

    def __init__(self, replay_mode: bool = True):
        """
        replay_mode : pour les données HISTORIQUES rejouées (datasets comme
        flaws.cloud, analyse forensique a posteriori). Aligne ingest_time sur
        event_time pour éviter les faux positifs de "clock skew" (l'écart entre
        le moment de l'événement et le moment du rejeu n'est PAS une falsification).
        Mettre False pour un flux temps réel (ingestion en direct).
        """
        self.replay_mode = replay_mode

    def parse(self, raw_content: str) -> list[CanonicalLog]:
        data = json.loads(raw_content)
        records = data.get("Records", []) if isinstance(data, dict) else data
        logs = []
        for rec in records:
            try:
                logs.append(self._to_canonical(rec))
            except Exception as e:
                # un événement malformé ne casse pas tout le lot
                # (le Collect Agent tracera les rejets à son niveau si besoin)
                continue
        return logs

    def parse_file(self, path: str) -> list[CanonicalLog]:
        """Lit un fichier .json ou .json.gz (format flaws.cloud)."""
        if path.endswith(".gz"):
            with gzip.open(path, "rt", encoding="utf-8") as f:
                return self.parse(f.read())
        with open(path, "r", encoding="utf-8") as f:
            return self.parse(f.read())

    def map_activity(self, native_event: dict) -> ActivityCategory:
        name = native_event.get("eventName", "")
        # correspondance exacte, sinon filet OTHER
        return _ACTION_PREFIX_MAP.get(name, ActivityCategory.OTHER)

    def _to_canonical(self, rec: dict) -> CanonicalLog:
        # --- temps ---
        event_time = self._parse_time(rec.get("eventTime"))

        # --- acteur (QUI) : userIdentity + IP + userAgent ---
        ui = rec.get("userIdentity", {}) or {}
        session_ctx = ui.get("sessionContext", {}) or {}
        session_attrs = session_ctx.get("attributes", {}) or {}
        # clé de corrélation cloud : arn + creationDate de session (remplace ProcessGUID)
        session_id = session_attrs.get("creationDate") or ui.get("accessKeyId")

        actor = Actor(
            user_id=ui.get("arn") or ui.get("principalId"),
            user_name=ui.get("userName"),
            session_id=session_id,
            source_ip=rec.get("sourceIPAddress"),
            user_agent=rec.get("userAgent"),
            account_id=ui.get("accountId"),
            principal_type=ui.get("type"),   # IAMUser, AssumedRole, Root, AWSService...
        )

        # --- outcome (succès / échec) ---
        outcome = Outcome.FAILURE if rec.get("errorCode") else Outcome.SUCCESS

        # --- contexte cloud (spécifique) ---
        service = (rec.get("eventSource", "") or "").replace(".amazonaws.com", "")
        cloud_ctx = CloudContext(
            provider="aws",
            region=rec.get("awsRegion"),
            service=service,
            api_call=rec.get("eventName"),
            resource_arn=self._extract_resource_arn(rec),
        )

        # --- cible (SUR QUOI) ---
        target = Target(
            type=service or None,
            name=self._extract_target_name(rec),
        )

        # en mode replay (données historiques), l'ingest_time = event_time
        # (sinon le "clock skew" ingest/event génère de faux positifs sur
        #  les datasets rejoués, qui datent souvent de plusieurs années)
        ingest_kwargs = {"ingest_time": event_time} if self.replay_mode else {}

        return CanonicalLog(
            source_type=SourceType.CLOUD_CONTROL,
            source_provider="aws_cloudtrail",
            event_time=event_time,
            **ingest_kwargs,
            activity=self.map_activity(rec),
            action_name=rec.get("eventName", "Unknown"),
            outcome=outcome,
            actor=actor,
            target=target,
            cloud_context=cloud_ctx,
            process_context=None,           # pas de processus dans le cloud control plane
            host=ui.get("arn") or ui.get("accountId"),  # "hôte" logique = le principal/compte
            raw_ref=rec.get("eventID"),
            extra={
                "errorCode": rec.get("errorCode"),
                "readOnly": rec.get("readOnly"),
                "eventType": rec.get("eventType"),
            },
        )

    # --- helpers ---
    def _parse_time(self, t: Optional[str]) -> datetime:
        if not t:
            return datetime.now(timezone.utc)
        # CloudTrail : ISO 8601, ex "2014-03-06T21:22:54Z"
        try:
            return datetime.fromisoformat(t.replace("Z", "+00:00"))
        except ValueError:
            return datetime.now(timezone.utc)

    def _extract_resource_arn(self, rec: dict) -> Optional[str]:
        # les ressources sont parfois listées dans un champ "resources"
        resources = rec.get("resources")
        if isinstance(resources, list) and resources:
            return resources[0].get("ARN") or resources[0].get("arn")
        return None

    def _extract_target_name(self, rec: dict) -> Optional[str]:
        params = rec.get("requestParameters") or {}
        if not isinstance(params, dict):
            return None
        # heuristiques courantes : nom de bucket, d'instance, d'utilisateur...
        for key in ("bucketName", "instanceId", "userName", "roleName",
                    "functionName", "name", "trailName"):
            if key in params:
                return str(params[key])
        return None


# -----------------------------------------------------------------------------
# Registre d'adaptateurs : sélectionne le bon selon le provider
# -----------------------------------------------------------------------------
class CloudAdapterRegistry:
    """
    Fabrique/registre : donne l'adaptateur du bon cloud.
    Pour ajouter Azure/GCP : implémenter CloudAdapter et l'enregistrer ici.
    """
    def __init__(self):
        self._adapters: dict[str, CloudAdapter] = {}
        # AWS fourni d'emblée
        self.register(AwsCloudTrailAdapter())

    def register(self, adapter: CloudAdapter):
        self._adapters[adapter.provider] = adapter

    def get(self, provider: str) -> Optional[CloudAdapter]:
        return self._adapters.get(provider)

    def providers(self) -> list[str]:
        return list(self._adapters)
