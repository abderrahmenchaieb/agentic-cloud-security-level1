"""
=============================================================================
RÉEXTRACTION DU LAB AVEC record_number
=============================================================================
⚠️ POURQUOI CE SCRIPT
    `comiset_travail.csv` (utilisé par E2 et E3) ne contient PAS de colonne
    de numéro d'enregistrement — perdue lors de l'export CSV d'origine.

    Conséquence mesurée dans E3 : `RecordGapDetector`, le détecteur
    DÉTERMINISTE de suppression de logs, ne s'active JAMAIS. Il lit
    `log.raw_ref`, peuplé depuis le champ `RecordNumber` du log brut — absent
    du CSV, donc toujours None, donc `check()` retourne None sans rien
    analyser.

    Seul `SilenceGapDetector` (statistique, basé sur le rythme d'émission)
    restait actif — avec une précision de 0.031 (358 déclenchements pour 11
    justes) sur un trafic Windows en rafales, dont la variance naturelle
    dépasse constamment son seuil `moyenne + 4σ`.

    La suppression de logs était donc mesurée à 0.000 de rappel dans E3, ce
    qui reflétait un mécanisme débranché, PAS une limite réelle de la méthode.

    Ce script régénère le CSV avec `record_number`, pour que le détecteur
    déterministe s'active et donne une mesure honnête.

⚠️ MÊME CONVENTION D'ÉTIQUETAGE QUE L'ORIGINAL
    `rule_technique_id` non vide = attaque. Le sous-échantillonnage du bénin
    reprend le TAUX_BENIN = 0.05 documenté pour la génération d'origine, afin
    que le nouveau CSV reste comparable aux mesures déjà effectuées.

USAGE
    unzip -p Comiset23_Lab_Environment_Dataset.zip dataset_comillas2.json \
      | python3 services/reextraire_lab_avec_record.py --sortie comiset_travail_v2.csv
=============================================================================
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import sys

# Colonnes de comiset_travail.csv, PLUS record_number.
# ⚠️ L'ordre et les noms des 16 premières colonnes sont conservés à
#    l'identique : les scripts existants (E2, E3) lisent par NOM, mais un
#    changement d'ordre casserait toute lecture positionnelle éventuelle.
_COLONNES = [
    "@timestamp", "event_original_time", "host_name", "process_guid",
    "process_name", "process_path", "event_id", "task",
    "target_process_guid", "target_process_name", "TargetObject",
    "user_name", "src_ip_addr", "command_line",
    "rule_technique_id", "rule_technique_name",
    "record_number",          # ← AJOUTÉ : active RecordGapDetector
]


def _lire_par_blocs(taille_bloc: int = 64 * 1024 * 1024):
    """
    ⚠️ Lecture par blocs binaires, PAS `for ligne in sys.stdin` : sous Git
    Bash/MSYS2, l'itération ligne par ligne sur un pipe plafonne à ~1,7 Mo/s
    alors que la décompression atteint 140-300 Mo/s (mesuré dans cette même
    campagne : 5h pour 30M lignes contre 43 min pour 202M après correction).
    """
    reste = b""
    flux = sys.stdin.buffer
    while True:
        bloc = flux.read(taille_bloc)
        if not bloc:
            break
        bloc = reste + bloc
        lignes = bloc.split(b"\n")
        reste = lignes.pop()
        for ligne_b in lignes:
            yield ligne_b
    if reste.strip():
        yield reste


def _ligne_csv(src: dict) -> dict:
    return {
        "@timestamp": src.get("@timestamp") or src.get("event_original_time") or "",
        "event_original_time": src.get("event_original_time") or "",
        "host_name": src.get("host_name") or "",
        "process_guid": src.get("process_guid") or "",
        "process_name": src.get("process_name") or "",
        "process_path": src.get("process_path") or "",
        "event_id": src.get("event_id") or "",
        "task": src.get("task") or "",
        "target_process_guid": src.get("target_process_guid") or "",
        "target_process_name": src.get("target_process_name") or "",
        "TargetObject": src.get("TargetObject") or "",
        "user_name": src.get("user_name") or "",
        "src_ip_addr": src.get("src_ip_addr") or "",
        "command_line": src.get("command_line") or src.get("CommandLine") or "",
        "rule_technique_id": src.get("rule_technique_id") or "",
        "rule_technique_name": src.get("rule_technique_name") or "",
        "record_number": src.get("record_number") if src.get("record_number") is not None else "",
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--sortie", default="comiset_travail_v2.csv")
    p.add_argument("--taux-benin", type=float, default=0.05,
                   help="proportion du bénin conservée — 0.05 reprend le "
                        "TAUX_BENIN de la génération d'origine, pour que le "
                        "nouveau CSV reste comparable aux mesures déjà faites")
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args()

    rng = random.Random(args.seed)
    f = open(args.sortie, "w", newline="", encoding="utf-8")
    w = csv.DictWriter(f, fieldnames=_COLONNES)
    w.writeheader()

    n_total = n_ecrits = n_attaques = n_avec_record = 0
    try:
        for ligne_b in _lire_par_blocs():
            n_total += 1
            if n_total % 5_000_000 == 0:
                print(f"  {n_total:,} lus | écrits {n_ecrits:,} "
                      f"(dont {n_attaques:,} attaques)",
                      file=sys.stderr, flush=True)
            if not ligne_b.strip():
                continue
            try:
                doc = json.loads(ligne_b)
            except json.JSONDecodeError:
                continue
            src = doc.get("_source")
            if not isinstance(src, dict):
                continue

            est_attaque = bool(src.get("rule_technique_id"))
            # toutes les attaques, 5 % du bénin — comme l'original
            if not est_attaque and rng.random() >= args.taux_benin:
                continue

            ligne = _ligne_csv(src)
            if ligne["record_number"] != "":
                n_avec_record += 1
            w.writerow(ligne)
            n_ecrits += 1
            if est_attaque:
                n_attaques += 1
    except (KeyboardInterrupt, BrokenPipeError, OSError) as e:
        print(f"\n  interrompu à {n_total:,} lignes : {e}", file=sys.stderr)
    finally:
        f.close()

    print(f"\n{n_total:,} documents lus", file=sys.stderr)
    print(f"  écrits    : {n_ecrits:,} ({n_attaques:,} attaques, "
          f"{n_ecrits - n_attaques:,} bénins)", file=sys.stderr)
    couverture = n_avec_record / n_ecrits if n_ecrits else 0.0
    print(f"  avec record_number : {n_avec_record:,} ({couverture:.1%})",
          file=sys.stderr)
    if couverture < 0.5:
        print(f"  ⚠️ Moins de la moitié des lignes portent un record_number —",
              file=sys.stderr)
        print(f"     RecordGapDetector ne sera que partiellement actif.",
              file=sys.stderr)
    print(f"  sortie : {args.sortie}", file=sys.stderr)


if __name__ == "__main__":
    main()
