#!/usr/bin/env python3
"""
=============================================================================
EXPLORATION COMPLÈTE — COMISET Real Environment (934 Go, un seul passage)
=============================================================================
Objectif : extraire TOUTE l'information nécessaire pour concevoir le bon
découpage entraînement/test, SANS jamais charger le fichier en mémoire et
SANS le relire plusieurs fois — un seul passage séquentiel sur le flux.

⚠️ POURQUOI UN SEUL PASSAGE
    Relire 934 Go plusieurs fois pour répondre à chaque question coûterait
    des heures à chaque fois. Ce script collecte TOUTES les statistiques en
    une seule lecture : hôtes, dates, techniques, EventID, volumétrie par
    jour et par hôte, exemples de chaque technique rencontrée.

CE QUI EST COLLECTÉ
    1. Hôtes distincts et volume par hôte
    2. Étendue temporelle réelle (première/dernière date)
    3. Volume par jour (pour repérer les pics d'attaque)
    4. Toutes les techniques MITRE et leur fréquence
    5. Répartition technique × hôte × jour (pour un découpage propre)
    6. EventID les plus fréquents, et lesquels portent une étiquette
    7. Un exemple COMPLET de chaque technique rencontrée
    8. Taux d'étiquetage global

USAGE (en streaming depuis le zip, sans jamais l'extraire entièrement)
    unzip -p Comiset23_Real_Environment_Dataset.zip \
        Comiset23_Real_Environment_Dataset.json \
      | python3 explorer_real.py > rapport_real.json

    Avec suivi de progression toutes les 5 millions de lignes (stderr) :
    ... | python3 explorer_real.py --progres 5000000 2> progres.log > rapport_real.json
=============================================================================
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict


def construire_rapport(n_total, n_json_invalide, n_avec_source, n_etiquetes,
                       hotes, dates_par_jour, event_ids, event_ids_etiquetes,
                       source_names, techniques, technique_x_hote,
                       technique_x_jour, technique_x_eventid,
                       exemples_par_technique, premiere_date, derniere_date,
                       complet: bool) -> dict:
    return {
        "etat": "complet" if complet else "PARTIEL (interrompu ou en cours)",
        "volumetrie": {
            "documents_lus": n_total,
            "json_invalides": n_json_invalide,
            "avec_source": n_avec_source,
            "etiquetes": n_etiquetes,
            "taux_etiquetage": round(n_etiquetes / n_avec_source, 6)
                              if n_avec_source else 0.0,
        },
        "periode": {
            "premier_jour": premiere_date,
            "dernier_jour": derniere_date,
            "n_jours_distincts": len(dates_par_jour),
        },
        "volume_par_jour": dict(dates_par_jour.most_common()),
        "hotes": {
            "n_hotes_distincts": len(hotes),
            "volume_par_hote": dict(hotes.most_common(50)),
        },
        "sources": dict(source_names.most_common(20)),
        "event_ids": {
            "tous": dict(event_ids.most_common(30)),
            "portant_une_etiquette": dict(event_ids_etiquetes.most_common(30)),
        },
        "techniques": {
            "frequence": dict(techniques.most_common()),
            "hotes_par_technique": {
                t: dict(c.most_common(20)) for t, c in technique_x_hote.items()
            },
            "jours_par_technique": {
                t: dict(c.most_common(40)) for t, c in technique_x_jour.items()
            },
            "eventid_par_technique": {
                t: dict(c.most_common(10)) for t, c in technique_x_eventid.items()
            },
        },
        "exemples": exemples_par_technique,
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--progres", type=int, default=2_000_000,
                   help="afficher la progression tous les N documents")
    p.add_argument("--exemples-max", type=int, default=2,
                   help="nombre d'exemples complets conservés par technique")
    p.add_argument("--checkpoint", default="rapport_partiel.json",
                   help="fichier de sauvegarde intermédiaire, réécrit "
                        "périodiquement — permet d'arrêter à tout moment "
                        "sans perdre le travail accompli")
    p.add_argument("--checkpoint-toutes-les", type=int, default=1_000_000,
                   help="sauvegarder tous les N documents (~2 minutes sur "
                        "un débit de 500k lignes/min)")
    args = p.parse_args()

    # --- accumulateurs ------------------------------------------------
    n_total = 0
    n_json_invalide = 0
    n_avec_source = 0
    n_etiquetes = 0

    hotes = Counter()
    dates_par_jour = Counter()
    event_ids = Counter()
    event_ids_etiquetes = Counter()
    source_names = Counter()

    techniques = Counter()
    technique_x_hote = defaultdict(Counter)      # {technique: {hote: n}}
    technique_x_jour = defaultdict(Counter)      # {technique: {jour: n}}
    technique_x_eventid = defaultdict(Counter)

    exemples_par_technique: dict[str, list] = defaultdict(list)

    premiere_date, derniere_date = None, None

    # --- passage unique, avec checkpoints périodiques -------------------
    #     ⚠️ INDISPENSABLE sur un fichier de 934 Go : le traitement peut
    #     durer plusieurs heures. Sans sauvegarde intermédiaire, toute
    #     interruption (Ctrl+C, coupure, décision d'arrêter) perd TOUT le
    #     travail déjà accompli. Ici, un rapport EXPLOITABLE existe dès le
    #     premier checkpoint, quelques minutes après le démarrage.
    interrompu = False
    try:
        for ligne in sys.stdin:
            n_total += 1
            if args.progres and n_total % args.progres == 0:
                print(f"  {n_total:,} documents traités…", file=sys.stderr, flush=True)

            if n_total % args.checkpoint_toutes_les == 0:
                rap = construire_rapport(
                    n_total, n_json_invalide, n_avec_source, n_etiquetes,
                    hotes, dates_par_jour, event_ids, event_ids_etiquetes,
                    source_names, techniques, technique_x_hote,
                    technique_x_jour, technique_x_eventid,
                    exemples_par_technique, premiere_date, derniere_date,
                    complet=False)
                with open(args.checkpoint, "w", encoding="utf-8") as f:
                    json.dump(rap, f, ensure_ascii=False, indent=2, default=str)
                print(f"  [checkpoint] {n_total:,} documents → "
                      f"{args.checkpoint}", file=sys.stderr, flush=True)

            ligne = ligne.strip()
            if not ligne:
                continue
            try:
                doc = json.loads(ligne)
            except json.JSONDecodeError:
                n_json_invalide += 1
                continue

            src = doc.get("_source")
            if not isinstance(src, dict):
                continue
            n_avec_source += 1

            hote = src.get("host_name") or "?"
            hotes[hote] += 1

            horodatage = src.get("@timestamp") or src.get("event_original_time") or ""
            jour = horodatage[:10] if len(horodatage) >= 10 else "?"
            if jour != "?":
                dates_par_jour[jour] += 1
                if premiere_date is None or jour < premiere_date:
                    premiere_date = jour
                if derniere_date is None or jour > derniere_date:
                    derniere_date = jour

            eid = str(src.get("event_id") or "?")
            event_ids[eid] += 1

            sname = src.get("source_name") or "?"
            source_names[sname] += 1

            technique = src.get("rule_technique_id")
            if technique:
                n_etiquetes += 1
                techniques[technique] += 1
                technique_x_hote[technique][hote] += 1
                technique_x_jour[technique][jour] += 1
                technique_x_eventid[technique][eid] += 1
                event_ids_etiquetes[eid] += 1

                if len(exemples_par_technique[technique]) < args.exemples_max:
                    plat = {k: v for k, v in src.items()
                            if not isinstance(v, (dict, list))}
                    exemples_par_technique[technique].append(plat)
    except KeyboardInterrupt:
        interrompu = True
        print(f"\n  interrompu par l'utilisateur à {n_total:,} documents — "
              f"écriture du rapport final avec ce qui a été accumulé.",
              file=sys.stderr, flush=True)
    except BrokenPipeError:
        interrompu = True
        print(f"\n  flux source interrompu à {n_total:,} documents — "
              f"écriture du rapport final.", file=sys.stderr, flush=True)

    # --- rapport final, TOUJOURS écrit, complet ou partiel -----------------
    rapport = construire_rapport(
        n_total, n_json_invalide, n_avec_source, n_etiquetes,
        hotes, dates_par_jour, event_ids, event_ids_etiquetes,
        source_names, techniques, technique_x_hote, technique_x_jour,
        technique_x_eventid, exemples_par_technique, premiere_date,
        derniere_date, complet=not interrompu)

    json.dump(rapport, sys.stdout, ensure_ascii=False, indent=2, default=str)
    with open(args.checkpoint, "w", encoding="utf-8") as f:
        json.dump(rapport, f, ensure_ascii=False, indent=2, default=str)
    print(f"\n\n{n_total:,} documents traités au total"
          f"{' (INTERROMPU — rapport partiel mais exploitable)' if interrompu else ' (complet)'}.",
          file=sys.stderr)


if __name__ == "__main__":
    main()
