# =============================================================================
# CORRÉLATEUR — regroupe les signaux par entité
# =============================================================================
# Le maillon critique du Decision Agent. Il rassemble les signaux qui parlent
# de la MÊME entité, autour de la MENACE comme pivot (corrélation pilotée par
# la menace, décidée en conception).
#
# Logique :
#   1. Chaque signal de MENACE (Analysis) ouvre une entité corrélée.
#   2. On y rattache les signaux d'ANONYMISATION dont l'IP recoupe les IPs
#      externes de la menace (lien par IP).
#   3. On y rattache les signaux d'INTÉGRITÉ (Collect) du même host, dans la
#      fenêtre temporelle (lien par host).
#
# Cas particuliers gérés :
#   - Intégrité SANS menace : une falsification/gap seul, sans attaque détectée,
#     produit quand même une entité (c'est un signal faible mais réel — ex :
#     quelqu'un efface des logs sans qu'on ait vu l'attaque). On ne le perd pas.
#   - Anonymisation SANS menace : ignorée ici (un VPN seul n'est pas un sujet ;
#     décidé en conception — l'anonymisation n'oriente que si une menace existe).
# =============================================================================

from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional
import uuid

from .decision_schema import (
    NormalizedSignal, SignalKind, CorrelatedEntity,
)


@dataclass
class CorrelatorConfig:
    # fenêtre temporelle de corrélation (les signaux au-delà ne sont pas liés)
    time_window_seconds: float = 300.0
    # rattacher les anomalies d'intégrité sans menace ? (entité "intégrité seule")
    keep_orphan_integrity: bool = True


class Correlator:
    """Regroupe les signaux normalisés en entités corrélées."""

    def __init__(self, config: Optional[CorrelatorConfig] = None):
        self.config = config or CorrelatorConfig()

    def correlate(self, signals: list[NormalizedSignal]) -> list[CorrelatedEntity]:
        threats = [s for s in signals if s.kind == SignalKind.THREAT]
        anons = [s for s in signals if s.kind == SignalKind.ANONYMIZATION]
        integrities = [s for s in signals if s.kind == SignalKind.INTEGRITY]

        entities: list[CorrelatedEntity] = []
        used_integrity: set[int] = set()   # indices d'intégrité déjà rattachés

        # --- 1. Chaque menace ouvre une entité (pivot) ---
        for threat in threats:
            entity = CorrelatedEntity(
                entity_key=f"ent-{uuid.uuid4().hex[:8]}",
                host=threat.host,
                threat_signal=threat,
            )

            # 2. rattacher les anonymisations liées par IP
            threat_ips = set(threat.ips)
            for anon in anons:
                if threat_ips & set(anon.ips):     # intersection d'IP
                    entity.anonymization_signals.append(anon)

            # 3. rattacher les intégrités du même host
            for i, integ in enumerate(integrities):
                if integ.host and integ.host == threat.host:
                    entity.integrity_signals.append(integ)
                    used_integrity.add(i)

            entities.append(entity)

        # --- 4. Intégrités orphelines (falsification/gap sans menace) ---
        if self.config.keep_orphan_integrity:
            orphans_by_host: dict[str, list[NormalizedSignal]] = {}
            for i, integ in enumerate(integrities):
                if i in used_integrity:
                    continue
                key = integ.host or "unknown"
                orphans_by_host.setdefault(key, []).append(integ)

            for host, integ_list in orphans_by_host.items():
                entities.append(CorrelatedEntity(
                    entity_key=f"ent-{uuid.uuid4().hex[:8]}",
                    host=host if host != "unknown" else None,
                    threat_signal=None,               # pas de menace
                    integrity_signals=integ_list,
                ))

        return entities

    def correlate_one(self, threat: NormalizedSignal,
                      anons: list[NormalizedSignal],
                      integrities: list[NormalizedSignal]) -> CorrelatedEntity:
        """
        Variante "pilotée par la menace" : pour UNE menace qui arrive, aller
        chercher les signaux corrélés (mode événementiel, temps réel).
        """
        entity = CorrelatedEntity(
            entity_key=f"ent-{uuid.uuid4().hex[:8]}",
            host=threat.host,
            threat_signal=threat,
        )
        threat_ips = set(threat.ips)
        for anon in anons:
            if threat_ips & set(anon.ips):
                entity.anonymization_signals.append(anon)
        for integ in integrities:
            if integ.host and integ.host == threat.host:
                entity.integrity_signals.append(integ)
        return entity
