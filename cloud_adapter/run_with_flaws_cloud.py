#!/usr/bin/env python3
"""
Point d'entrée : brancher flaws.cloud / flaws2.cloud sur le système.

flaws.cloud et flaws2.cloud sont des CTF AWS dont les logs CloudTrail sont
publics et TÉLÉCHARGEABLES (sans compte cloud requis) :
  - flaws.cloud  : ~3,5 ans de CloudTrail réel (attaques variées), ~240 Mo
  - flaws2.cloud : les logs CloudTrail d'une compromission complète documentée
    (bucket public s3://flaws2_logs, sous AWSLogs/.../CloudTrail/...)

VÉRITÉ TERRAIN (anti-circularité) : les scénarios d'attaque de chaque niveau
sont documentés publiquement (write-ups). On dérive les labels MITRE de cette
DOCUMENTATION, pas d'un LLM — ce qui évite la circularité (on n'évalue pas un
LLM avec des labels produits par un LLM). Un LLM peut servir d'ASSISTANT de
pré-tri, mais la vérité terrain vient des write-ups / d'une revue manuelle.

Usage :
    python run_with_flaws_cloud.py <dossier_ou_fichier_cloudtrail>

Le dossier peut contenir des .json.gz (format natif flaws.cloud).
"""
import sys
import os
import glob

from cloud_adapter import AwsCloudTrailAdapter, process_canonical_logs


def load_flaws_cloud(path: str, replay: bool = True):
    """
    Charge les logs CloudTrail de flaws.cloud (fichier ou dossier de .json/.json.gz).
    replay=True : données historiques → pas de faux clock skew.
    """
    adapter = AwsCloudTrailAdapter(replay_mode=replay)
    files = []
    if os.path.isdir(path):
        files = sorted(glob.glob(os.path.join(path, "**", "*.json*"), recursive=True))
    else:
        files = [path]

    all_logs = []
    for fp in files:
        try:
            logs = adapter.parse_file(fp)
            all_logs.extend(logs)
        except Exception as e:
            print(f"  [!] {fp}: {e}")
    print(f"Chargé {len(all_logs)} événements CloudTrail depuis {len(files)} fichier(s)")
    return all_logs


def main(path: str):
    # 1. adaptateur : CloudTrail → canonique
    canonical = load_flaws_cloud(path)
    if not canonical:
        print("Aucun log chargé. Vérifie le chemin.")
        return

    # 2. Collect Agent : intégrité (falsification / gaps) sur les logs cloud
    #    (nécessite le package collect_agent dans le PYTHONPATH)
    try:
        from collect_agent.collect_agent import CollectAgent
    except ImportError:
        print("Ajoute le package collect_agent au PYTHONPATH pour l'étape d'intégrité.")
        print("Exemple : export PYTHONPATH=/chemin/vers/1_collect_agent")
        return

    collect = CollectAgent()
    outputs = process_canonical_logs(collect, canonical)
    print(f"\nCollect Agent (intégrité) : {collect.stats}")
    if outputs.gaps:
        print(f"Gaps détectés (suppressions possibles) :")
        for g in outputs.gaps[:10]:
            print(f"  - {g.detail}")

    # 3. étapes suivantes (à brancher) :
    #    - sequence builder CLOUD (corrélation par session/principal) → Analysis
    #    - RAG MITRE for Cloud
    #    - Anonymization sur les IP sources (actor.source_ip)
    print("\nProchaines étapes : sequence builder cloud + RAG MITRE for Cloud.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python run_with_flaws_cloud.py <dossier_ou_fichier_cloudtrail>")
        print("\nPour obtenir les données :")
        print("  flaws2.cloud : aws s3 sync --no-sign-request s3://flaws2-logs/ ./flaws2_logs/")
        print("  (voir les write-ups flaws.cloud pour la vérité terrain des scénarios)")
        sys.exit(1)
    main(sys.argv[1])
