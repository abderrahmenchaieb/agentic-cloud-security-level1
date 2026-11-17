# =============================================================================
# CONTRAT D'ENTRÉE — Decision Agent
# =============================================================================
# Le Decision Agent reçoit des signaux HÉTÉROGÈNES de trois sources :
#   - Analysis        : ThreatVerdict (menace + techniques + artefacts)
#   - Anonymization   : AnonymizationVerdict (VPN/Tor sur une IP)
#   - Collect         : gaps + flags d'intégrité (falsification/suppression)
#
# Problème : ils n'ont ni le même format ni la même notion d'"entité".
# Solution : on les NORMALISE vers un signal commun (NormalizedSignal),
# corrélable par host (Analysis↔Collect) et par IP (Analysis↔Anonymization).
#
# L'Analysis Agent est le PIVOT : il a le host ET les IPs externes, donc il
# relie les deux autres. C'est cohérent avec la corrélation pilotée par la menace.
# =============================================================================

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Any


class SignalSource(str, Enum):
    ANALYSIS = "analysis"            # menace (ThreatVerdict)
    ANONYMIZATION = "anonymization"  # VPN/Tor (AnonymizationVerdict)
    COLLECT = "collect"              # intégrité (gaps, falsification)


class SignalKind(str, Enum):
    THREAT = "threat"                # une attaque détectée
    ANONYMIZATION = "anonymization"  # une technique d'anonymisation
    INTEGRITY = "integrity"          # une anomalie de données (falsif/gap)


@dataclass
class NormalizedSignal:
    """
    Un signal unifié, quelle que soit sa source.
    C'est la forme commune que le corrélateur manipule.
    """
    source: SignalSource
    kind: SignalKind
    # clés de corrélation
    host: Optional[str] = None
    ips: list[str] = field(default_factory=list)   # IPs externes concernées
    event_time: Optional[datetime] = None
    # intensité du signal (normalisée 0..1 quand c'est un score)
    severity: float = 0.0
    # le verdict d'origine (préservé tel quel pour l'exploitation aval)
    payload: Any = None
    # détail lisible
    detail: str = ""


@dataclass
class CorrelatedEntity:
    """
    Résultat du corrélateur : tous les signaux qui parlent de la MÊME entité
    (même host, fenêtre temporelle proche), reliés entre eux.

    Le threat_signal est central (pivot). Les signaux d'anonymisation et
    d'intégrité qui lui sont liés (par IP / par host) sont rattachés.
    """
    entity_key: str                              # host:fenêtre
    host: Optional[str] = None
    window_start: Optional[datetime] = None
    window_end: Optional[datetime] = None

    threat_signal: Optional[NormalizedSignal] = None          # de l'Analysis
    anonymization_signals: list[NormalizedSignal] = field(default_factory=list)  # de l'Anon
    integrity_signals: list[NormalizedSignal] = field(default_factory=list)      # du Collect

    def has_threat(self) -> bool:
        return self.threat_signal is not None

    def has_anonymization(self) -> bool:
        return len(self.anonymization_signals) > 0

    def has_integrity_issue(self) -> bool:
        return len(self.integrity_signals) > 0

    def threat_score(self) -> float:
        return self.threat_signal.severity if self.threat_signal else 0.0

    def max_anonymization_score(self) -> float:
        return max((s.severity for s in self.anonymization_signals), default=0.0)

    def anonymization_labels(self) -> list[str]:
        """Types d'anonymisation détectés (tor, vpn)."""
        labels = []
        for s in self.anonymization_signals:
            lbl = s.detail  # on stocke le label dans detail à la normalisation
            if lbl and lbl not in labels:
                labels.append(lbl)
        return labels

    def observed_artifacts(self) -> list[str]:
        """Artefacts observés (portés par le signal de menace de l'Analysis)."""
        if self.threat_signal and self.threat_signal.payload:
            return getattr(self.threat_signal.payload, "observed_artifacts", []) or \
                   (self.threat_signal.payload.get("observed_artifacts", [])
                    if isinstance(self.threat_signal.payload, dict) else [])
        return []

    def techniques(self) -> list:
        """Techniques MITRE portées par le signal de menace."""
        if self.threat_signal and self.threat_signal.payload:
            p = self.threat_signal.payload
            if isinstance(p, dict):
                return p.get("techniques", [])
            return getattr(p, "techniques", []) or []
        return []

    def summary(self) -> dict:
        return {
            "entity_key": self.entity_key,
            "host": self.host,
            "threat_score": round(self.threat_score(), 3),
            "has_anonymization": self.has_anonymization(),
            "anonymization_labels": self.anonymization_labels(),
            "has_integrity_issue": self.has_integrity_issue(),
            "observed_artifacts": self.observed_artifacts(),
            "n_techniques": len(self.techniques()),
        }
