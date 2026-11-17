# =============================================================================
# PONT ADAPTATEUR CLOUD → COLLECT AGENT
# =============================================================================
# Le Collect Agent mappe Sysmon en dur (map_sysmon_event) au début de process().
# Mais tout le TRAITEMENT D'INTÉGRITÉ qui suit (règles forensiques, gaps, ML,
# routage) est GÉNÉRIQUE : il travaille sur des CanonicalLog, quelle que soit
# la source.
#
# Ce pont réutilise ce traitement générique pour les CanonicalLog produits par
# l'adaptateur cloud — SANS modifier le Collect Agent. On injecte les logs déjà
# mappés (cloud) dans le même pipeline d'intégrité.
#
# Résultat : la détection de falsification/gaps du Collect s'applique AUSSI au
# cloud (ex : un StopLogging = manipulation du logging ; un saut dans la
# séquence d'événements = suppression).
# =============================================================================

from __future__ import annotations
from datetime import datetime, timezone

from collect_agent.canonical_schema import CanonicalLog, ActivityCategory
# on réutilise les mêmes structures de sortie que le Collect
from collect_agent.collect_agent import (
    EnrichedLog, IntegrityAnnotation, FlowRecord, _safe_int,
)


def process_canonical_logs(collect_agent, canonical_logs: list[CanonicalLog]):
    """
    Injecte des CanonicalLog (déjà mappés, ex: cloud) dans le pipeline
    d'intégrité du Collect Agent, en réutilisant ses moteurs (forensique, gaps,
    ML) sans repasser par le mapping Sysmon.

    Retourne les CollectOutputs du Collect (enriched, flows, gaps, rejected).
    """
    for log in canonical_logs:
        collect_agent.stats["processed"] += 1
        annotations: list[IntegrityAnnotation] = []

        # [2] Règles forensiques (génériques : travaillent sur CanonicalLog)
        for tf in collect_agent.forensic_engine.analyze(log):
            collect_agent.stats["tampering"] += 1
            annotations.append(IntegrityAnnotation(
                kind="tampering_rule", confidence=tf.confidence,
                detail=f"[{tf.rule_id}] {tf.detail}",
                extra={"tamper_type": tf.tamper_type.value},
            ))

        # [3] Détection de gaps (générique : source_key + record + temps)
        gap_findings = collect_agent.gap_engine.analyze_log(
            collect_agent._source_key(log),
            log.raw_ref and _safe_int(log.raw_ref), log.event_time,
        )
        for gf in gap_findings:
            collect_agent.stats["gaps"] += 1
            collect_agent.outputs.gaps.append(gf)
            annotations.append(IntegrityAnnotation(
                kind="gap", confidence="high", detail=gf.detail,
                extra={"gap_type": gf.gap_type.value, "severity": gf.severity_score},
            ))

        # [4] ML d'anomalie (si activé) — générique
        if collect_agent.anomaly_detector is not None and collect_agent.ml_threshold is not None:
            finding = collect_agent.anomaly_detector.score(log)
            if finding.raw_score < collect_agent.ml_threshold:
                annotations.append(IntegrityAnnotation(
                    kind="tampering_ml", confidence="medium",
                    detail=f"anomalie ML (score {finding.raw_score:.3f})",
                    extra={"top_features": finding.top_features},
                ))

        # Routage : enriched
        collect_agent.outputs.enriched.append(EnrichedLog(log=log, annotations=annotations))

        # Routage : flows (si événement réseau — rare dans le control plane,
        # mais l'IP source est portée par l'acteur pour l'Anonymization)
        if log.activity == ActivityCategory.NETWORK_CONNECTION and log.target:
            collect_agent.outputs.flows.append(FlowRecord(
                event_id=log.event_id,
                source_ip=log.actor.source_ip if log.actor else None,
                destination_ip=log.target.destination_ip,
                destination_port=log.target.destination_port,
                protocol=log.target.protocol,
                event_time=log.event_time.isoformat(),
            ))

    return collect_agent.outputs
