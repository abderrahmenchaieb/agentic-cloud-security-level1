#!/usr/bin/env python3
"""
Point d'entrée : brancher COMISET sur le Collect Agent.

Ce script montre le workflow complet avec de VRAIES données :
  1. charger COMISET (logs Sysmon JSON)
  2. mapper vers le schéma canonique + séparer le corpus intègre
  3. entraîner le ML d'anomalie sur le corpus intègre
  4. calibrer le seuil ML sur le normal
  5. générer des falsifications (jeu de test à vérité terrain)
  6. lancer l'ablation : règles seules VS règles + ML
  7. faire tourner l'agent complet

À ADAPTER : la fonction load_comiset() selon le format exact des fichiers
COMISET que tu télécharges depuis Zenodo (DOI 10.5281/zenodo.15375146).
"""
import json
import sys
from pathlib import Path
import numpy as np

from collect_agent import (
    CollectAgent, AnomalyDetector, ForensicRuleEngine,
    FalsificationGenerator, FalsificationType,
    map_sysmon_event,
)


# -----------------------------------------------------------------------------
# 1. CHARGEMENT DE COMISET  (à adapter au format réel des fichiers)
# -----------------------------------------------------------------------------
def load_comiset(path: str) -> list[dict]:
    """
    Charge les événements Sysmon bruts depuis COMISET.

    COMISET est en JSON. Selon le fichier, ce peut être :
      - un tableau JSON d'événements, OU
      - du JSON-Lines (un événement par ligne).
    On gère les deux. ADAPTE les noms de champs si besoin après inspection.
    """
    raws = []
    p = Path(path)
    files = [p] if p.is_file() else sorted(p.glob("*.json"))
    for f in files:
        text = f.read_text(encoding="utf-8", errors="ignore").strip()
        try:
            data = json.loads(text)
            raws.extend(data if isinstance(data, list) else [data])
        except json.JSONDecodeError:
            # JSON-Lines
            for line in text.splitlines():
                line = line.strip()
                if line:
                    try:
                        raws.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    return raws


def normalize_comiset_fields(raw: dict) -> dict:
    """
    COMISET peut imbriquer les champs Sysmon (ex : sous 'winlog.event_data').
    Cette fonction aplatit vers les clés que map_sysmon_event attend :
      EventID, UtcTime, Computer, ProcessGuid, Image, CommandLine,
      ParentProcessGuid, ParentImage, DestinationIp, DestinationPort,
      Protocol, SourceIp, RecordNumber, User, LogonId, TargetFilename, ...

    ADAPTE ce mapping après avoir inspecté un échantillon réel de COMISET.
    """
    # Exemple de mapping défensif : on cherche les champs à plusieurs endroits.
    def pick(*keys, default=None):
        for k in keys:
            # clés imbriquées "a.b.c"
            cur = raw
            ok = True
            for part in k.split("."):
                if isinstance(cur, dict) and part in cur:
                    cur = cur[part]
                else:
                    ok = False
                    break
            if ok and cur not in (None, ""):
                return cur
        return default

    return {
        "EventID": pick("EventID", "winlog.event_id", "event.code"),
        "UtcTime": pick("UtcTime", "winlog.event_data.UtcTime", "@timestamp"),
        "Computer": pick("Computer", "winlog.computer_name", "host.name"),
        "ProcessGuid": pick("ProcessGuid", "winlog.event_data.ProcessGuid"),
        "ProcessId": pick("ProcessId", "winlog.event_data.ProcessId"),
        "Image": pick("Image", "winlog.event_data.Image"),
        "CommandLine": pick("CommandLine", "winlog.event_data.CommandLine"),
        "ParentProcessGuid": pick("ParentProcessGuid", "winlog.event_data.ParentProcessGuid"),
        "ParentProcessId": pick("ParentProcessId", "winlog.event_data.ParentProcessId"),
        "ParentImage": pick("ParentImage", "winlog.event_data.ParentImage"),
        "DestinationIp": pick("DestinationIp", "winlog.event_data.DestinationIp"),
        "DestinationPort": pick("DestinationPort", "winlog.event_data.DestinationPort"),
        "Protocol": pick("Protocol", "winlog.event_data.Protocol"),
        "SourceIp": pick("SourceIp", "winlog.event_data.SourceIp"),
        "User": pick("User", "winlog.event_data.User"),
        "LogonId": pick("LogonId", "winlog.event_data.LogonId"),
        "IntegrityLevel": pick("IntegrityLevel", "winlog.event_data.IntegrityLevel"),
        "TargetFilename": pick("TargetFilename", "winlog.event_data.TargetFilename"),
        "TargetObject": pick("TargetObject", "winlog.event_data.TargetObject"),
        "TargetImage": pick("TargetImage", "winlog.event_data.TargetImage"),
        "TargetProcessGuid": pick("TargetProcessGuid", "winlog.event_data.TargetProcessGuid"),
        # numéro de séquence : COMISET a EventRecordID
        "RecordNumber": pick("RecordNumber", "EventRecordID",
                             "winlog.record_id", "winlog.event_record_id"),
    }


# -----------------------------------------------------------------------------
# 2. WORKFLOW COMPLET
# -----------------------------------------------------------------------------
def main(comiset_path: str):
    print(f"[1] Chargement de COMISET depuis {comiset_path} ...")
    raw_events = load_comiset(comiset_path)
    print(f"    {len(raw_events)} événements bruts chargés.")

    print("[2] Normalisation vers le schéma canonique ...")
    canonical = []
    for raw in raw_events:
        norm = normalize_comiset_fields(raw)
        result = map_sysmon_event(norm)
        if result.is_valid:
            canonical.append(result.log)
    print(f"    {len(canonical)} logs valides normalisés.")

    if len(canonical) < 100:
        print("    [!] Trop peu de logs valides — vérifie normalize_comiset_fields().")
        return

    # séparer corpus d'entraînement (intègre) / test
    # NOTE : idéalement, filtrer ici les logs BÉNINS de COMISET pour un
    # corpus "normal" pur (voir README, section 'corpus intègre').
    split = int(len(canonical) * 0.7)
    train_corpus = canonical[:split]
    test_corpus = canonical[split:]
    print(f"    train={len(train_corpus)}  test={len(test_corpus)}")

    print("[3] Entraînement du ML d'anomalie sur le corpus intègre ...")
    detector = AnomalyDetector(contamination=0.05)
    detector.fit(train_corpus)

    print("[4] Calibration du seuil ML sur le normal ...")
    raw_scores = np.array([detector.score(l).raw_score for l in test_corpus])
    threshold = float(np.percentile(raw_scores, 1))  # 1er percentile = frontière basse
    print(f"    seuil (raw_score) = {threshold:.4f}")

    print("[5] Génération de falsifications (jeu de test) ...")
    gen = FalsificationGenerator(seed=42)
    fdataset = gen.generate(test_corpus, ratio=0.10)
    print(f"    {fdataset.stats()}")

    print("[6] ABLATION : règles seules VS règles + ML ...")
    run_ablation(fdataset, detector, threshold)

    print("[7] Agent complet en fonctionnement ...")
    agent = CollectAgent(anomaly_detector=detector, ml_threshold=threshold)
    for raw in raw_events[:1000]:
        agent.process(normalize_comiset_fields(raw))
    print(f"    {agent.outputs.summary()}")
    print(f"    santé : {agent.stats}")


def run_ablation(fdataset, detector, threshold):
    """Compare la détection règles seules vs règles + ML sur le jeu falsifié."""
    rules = ForensicRuleEngine()
    tampered = fdataset.tampered_event_ids

    rules_caught = set()
    ml_caught = set()
    for log in fdataset.logs:
        if rules.analyze(log):
            rules_caught.add(log.event_id)
        if detector.score(log).raw_score < threshold:
            ml_caught.add(log.event_id)

    combined = rules_caught | ml_caught
    def recall(caught):
        return len(caught & tampered) / len(tampered) if tampered else 0.0

    print(f"      falsifications injectées : {len(tampered)}")
    print(f"      rappel RÈGLES seules     : {recall(rules_caught):.1%}")
    print(f"      rappel RÈGLES + ML       : {recall(combined):.1%}")
    ml_unique = (ml_caught & tampered) - rules_caught
    print(f"      apport UNIQUE du ML      : {len(ml_unique)} falsification(s) que les règles ratent")
    print("      → Si l'apport unique est significatif, le ML est justifié.")
    print("      → Sinon, les règles suffisent (résultat honnête à documenter).")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python run_with_comiset.py <chemin_vers_COMISET>")
        print("  (dossier de .json ou fichier unique)")
        sys.exit(1)
    main(sys.argv[1])
