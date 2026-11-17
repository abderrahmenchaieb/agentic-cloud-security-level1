# =============================================================================
# NORMALISEURS — traduisent les sorties des 3 agents vers NormalizedSignal
# =============================================================================
# Chaque agent produit un verdict avec sa propre structure. Ces fonctions
# les ramènent à la forme commune (NormalizedSignal), en extrayant les clés
# de corrélation (host, ips, temps) et l'intensité (severity).
#
# On accepte à la fois des objets (dataclasses des agents) ET des dicts
# (sérialisation JSON), pour rester robuste à la façon dont les signaux
# arrivent (en mémoire ou via un bus/file).
# =============================================================================

from __future__ import annotations
from datetime import datetime
from typing import Any, Optional

from .decision_schema import (
    NormalizedSignal, SignalSource, SignalKind,
)


def _get(obj: Any, name: str, default=None):
    """Accès uniforme attribut OU clé de dict."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


# -----------------------------------------------------------------------------
# ANALYSIS → NormalizedSignal (menace)
# -----------------------------------------------------------------------------
def normalize_threat(threat_verdict: Any) -> Optional[NormalizedSignal]:
    """
    ThreatVerdict de l'Analysis Agent → signal de menace.
    Ne normalise que les verdicts d'ATTAQUE (is_attack=True) ; les séquences
    normales ne produisent pas de signal.
    """
    is_attack = _get(threat_verdict, "is_attack", False)
    if not is_attack:
        return None

    host = _get(threat_verdict, "host")
    summary = _get(threat_verdict, "sequence_summary", {}) or {}
    ips = summary.get("external_ips", []) if isinstance(summary, dict) else \
          _get(summary, "external_ips", [])

    return NormalizedSignal(
        source=SignalSource.ANALYSIS,
        kind=SignalKind.THREAT,
        host=host,
        ips=list(ips or []),
        event_time=None,  # (le ThreatVerdict pourra porter un temps plus tard)
        severity=float(_get(threat_verdict, "attack_score", 0.0)),
        payload=threat_verdict,   # on garde tout (techniques, artefacts, hypothèse)
        detail=_get(threat_verdict, "hypothesis", "") or "",
    )


# -----------------------------------------------------------------------------
# ANONYMIZATION → NormalizedSignal (VPN/Tor)
# -----------------------------------------------------------------------------
def normalize_anonymization(anon_verdict: Any) -> Optional[NormalizedSignal]:
    """
    AnonymizationVerdict → signal d'anonymisation.
    On ne garde que les verdicts VPN/Tor (pas 'normal' ni 'unknown').
    """
    label = _get(anon_verdict, "label")
    # label peut être un enum (AnonymizationLabel) ou une string
    label_str = getattr(label, "value", label)
    if label_str not in ("vpn", "tor"):
        return None

    ext_ip = _get(anon_verdict, "external_ip")
    ips = [ext_ip] if ext_ip else []

    return NormalizedSignal(
        source=SignalSource.ANONYMIZATION,
        kind=SignalKind.ANONYMIZATION,
        host=None,                       # l'anonymisation est liée à une IP, pas un host
        ips=ips,
        event_time=None,
        severity=float(_get(anon_verdict, "confidence", 0.0)),
        payload=anon_verdict,
        detail=label_str,                # 'vpn' ou 'tor' (utilisé par anonymization_labels)
    )


# -----------------------------------------------------------------------------
# COLLECT → NormalizedSignal (intégrité : gaps + falsification)
# -----------------------------------------------------------------------------
def normalize_gap(gap_finding: Any) -> NormalizedSignal:
    """GapFinding du Collect Agent → signal d'intégrité."""
    source_key = _get(gap_finding, "source_key", "") or ""
    host = source_key.split(":")[0] if ":" in source_key else source_key
    return NormalizedSignal(
        source=SignalSource.COLLECT,
        kind=SignalKind.INTEGRITY,
        host=host or None,
        ips=[],
        event_time=_get(gap_finding, "detected_at"),
        severity=float(_get(gap_finding, "severity_score", 0.0)),
        payload=gap_finding,
        detail=_get(gap_finding, "detail", "") or "",
    )


def normalize_integrity_flag(host: str, flag_detail: str,
                             severity: float = 0.8) -> NormalizedSignal:
    """
    Annotation de falsification (héritée via les integrity_flags d'une séquence,
    ou directement du Collect Agent) → signal d'intégrité.
    """
    return NormalizedSignal(
        source=SignalSource.COLLECT,
        kind=SignalKind.INTEGRITY,
        host=host,
        ips=[],
        event_time=None,
        severity=severity,
        payload={"flag": flag_detail},
        detail=flag_detail,
    )


# -----------------------------------------------------------------------------
# Normalisation en lot
# -----------------------------------------------------------------------------
def normalize_all(threat_verdicts: list = None,
                  anon_verdicts: list = None,
                  gap_findings: list = None,
                  integrity_flags: list = None) -> list[NormalizedSignal]:
    """
    Normalise toutes les sorties d'un cycle en une liste de signaux.
    integrity_flags : liste de tuples (host, detail).
    """
    signals: list[NormalizedSignal] = []

    for tv in (threat_verdicts or []):
        s = normalize_threat(tv)
        if s:
            signals.append(s)

    for av in (anon_verdicts or []):
        s = normalize_anonymization(av)
        if s:
            signals.append(s)

    for gf in (gap_findings or []):
        signals.append(normalize_gap(gf))

    for item in (integrity_flags or []):
        # Rétrocompatible : (host, detail) OU (host, detail, severity).
        # La sévérité provient de la calibration Platt du Collect
        # (integrity_score.py) : c'est une probabilité calibrée de falsification.
        if len(item) == 3:
            host, detail, severity = item
            signals.append(normalize_integrity_flag(host, detail, severity))
        else:
            host, detail = item
            signals.append(normalize_integrity_flag(host, detail))

    return signals
