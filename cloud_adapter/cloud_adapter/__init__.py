"""
Cloud Adapter — couche d'adaptation cloud pour le système multi-agents.

Rend le système "adaptatif à n'importe quel cloud" par le pattern ADAPTATEUR :
un adaptateur par cloud traduit son format natif vers le schéma canonique.
Le reste du système (les 4 agents) ne change jamais — il ne voit que du
canonique. Ajouter un cloud = ajouter un adaptateur.

Composants :
    cloud_adapter      - CloudAdapter (interface), AwsCloudTrailAdapter (AWS),
                         CloudAdapterRegistry (sélection multi-cloud)
    cloud_to_collect   - pont : injecte les CanonicalLog cloud dans le pipeline
                         d'intégrité du Collect Agent (réutilise ses moteurs)

Format CloudTrail supporté : classique (array Records[]), .json et .json.gz
(format flaws.cloud). Clé de corrélation cloud : userIdentity/session
(remplace le ProcessGUID de Windows).
"""

from .cloud_adapter import (
    CloudAdapter, AwsCloudTrailAdapter, CloudAdapterRegistry,
)
from .cloud_to_collect import process_canonical_logs
from .cloud_sequence_builder import (
    canonical_to_cloud_events, CloudSequenceBuilder, CloudSequenceBuilderConfig,
)
from .mitre_cloud_sample import SAMPLE_CLOUD_TECHNIQUES

__version__ = "0.1.0"

__all__ = [
    "CloudAdapter", "AwsCloudTrailAdapter", "CloudAdapterRegistry",
    "process_canonical_logs",
    "canonical_to_cloud_events", "CloudSequenceBuilder", "CloudSequenceBuilderConfig",
    "SAMPLE_CLOUD_TECHNIQUES",
]
