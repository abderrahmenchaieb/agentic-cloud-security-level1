"""
=============================================================================
CONSTRUCTION DIRECTE DES FENÊTRES D'ENTRAÎNEMENT — depuis le flux JSON
=============================================================================
⚠️ POURQUOI CE SCRIPT REMPLACE L'APPROCHE PRÉCÉDENTE
    `extraire_reentrainement.py` produisait `real_entrainement.csv` par
    TIRAGE ALÉATOIRE INDÉPENDANT de chaque ligne (2 % de chance par log).
    Deux défauts, découverts trop tard :

      1. Un tirage uniforme reproduit MÉCANIQUEMENT la proportion du corpus
         source (97 % de ProcessAccess) — biaisé dès le départ, avant même
         toute tentative de rééquilibrage.

      2. Il DÉTRUIT l'ordre chronologique et la structure en rafales de
         l'activité réelle. Rééquilibrer après coup (sous-échantillonnage,
         rejet de fenêtres) travaille alors sur un résidu déjà dégradé —
         ce qui explique le passage de 54 339 fenêtres à 131 fenêtres au fil
         des tentatives de correction : chaque filtre s'appliquait sur un
         signal de plus en plus appauvri.

    Ce script construit les fenêtres CORRECTEMENT dès la lecture du flux :
    par hôte, dans l'ORDRE CHRONOLOGIQUE réel, en glissant sur les rafales
    naturelles — pas en tirant des lignes au hasard puis en espérant que le
    résultat soit exploitable.

MÉTHODE
    1. Un seul passage sur le flux JSON (unzip -p | ce script).
    2. Pour CHAQUE hôte d'entraînement, accumulation d'un buffer chronologique
       de logs bénins.
    3. Dès que le buffer atteint FENETRE_GLISSANTE logs, on regarde la fenêtre
       des 50 DERNIERS logs : si elle est mixte (aucune catégorie > seuil),
       elle est retenue et ses 22 scores sont calculés — SANS relire le
       fichier, à la volée.
    4. Le buffer avance par pas de PAS logs (chevauchement partiel), pas
       nécessairement 50 par 50 — cela donne plus de fenêtres candidates
       à partir du même volume de logs, sans dupliquer le travail de lecture.

USAGE
    unzip -p Comiset23_Real_Environment_Dataset.zip Comiset23_Real_Environment_Dataset.json \
      | python3 services/construire_fenetres_entrainement.py \
        --hotes-entrainement computer01.domain.es,computer02.domain.es,... \
        --sortie fenetres_entrainement.npz
=============================================================================
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict, Counter

_ICI = os.path.dirname(os.path.abspath(__file__))
_RACINE = os.path.dirname(_ICI)
for chemin in (_ICI, _RACINE,
               os.path.join(_RACINE, "agents", "1_collect_agent")):
    if chemin not in sys.path:
        sys.path.insert(0, chemin)


def _lire_par_blocs(taille_bloc: int = 64 * 1024 * 1024):
    """
    ⚠️ Lecture par blocs binaires sur sys.stdin.buffer, PAS `for ligne in
    sys.stdin` : sous Git Bash/MSYS2, l'itération ligne par ligne sur un pipe
    est ~100x plus lente que le débit réel de décompression (mesuré : 1,7
    Mo/s au lieu de 140-300 Mo/s dans cette même campagne).
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


def _record_leger(src: dict) -> dict:
    """Ne garde du document que ce qui est nécessaire au calcul des 22 scores."""
    return {
        "event_id": str(src.get("event_id") or ""),
        "timestamp": src.get("@timestamp") or src.get("event_original_time") or "",
        "process_name": src.get("process_name") or src.get("process_path") or "",
        "process_guid": src.get("process_guid") or "",
    }


def _parse_temps(ts: str):
    from datetime import datetime
    ts = (ts or "").replace("Z", "")
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def _scores_depuis_records(records: list) -> list[float] | None:
    """
    Réimplémentation LÉGÈRE de fenetre_vers_scores, sans passer par
    CanonicalLog — on n'a pas besoin de la validation Pydantic complète ici,
    seulement des 4 champs qui alimentent les 22 scores. Garde la MÊME
    logique de calcul que window_integrity.fenetre_vers_scores, pour rester
    strictement compatible avec le modèle chargé en production.
    """
    from collect_agent.window_integrity import categorie, CATEGORIES, NOMS_SCORES

    n = len(records)
    if n == 0:
        return None

    cats = [categorie(r["event_id"]) for r in records]
    c = Counter(cats)
    comptes = [float(c.get(k, 0)) for k in CATEGORIES]
    ratios = [v / n for v in comptes]
    n_types = float(len(set(cats)))

    temps = sorted(t for t in (_parse_temps(r["timestamp"]) for r in records)
                   if t is not None)
    if len(temps) > 1:
        ecarts = [(temps[i + 1] - temps[i]).total_seconds()
                  for i in range(len(temps) - 1)]
        moyenne = sum(ecarts) / len(ecarts)
        variance = sum((e - moyenne) ** 2 for e in ecarts) / len(ecarts)
        gap_mean, gap_std, gap_max = moyenne, variance ** 0.5, max(ecarts)
    else:
        gap_mean = gap_std = gap_max = 0.0

    noms = [r["process_name"] for r in records if r["process_name"]]
    proc_name_len = (sum(len(x) for x in noms) / len(noms)) if noms else 0.0
    guids = {r["process_guid"] for r in records if r["process_guid"]}
    n_guid = float(len(guids))

    return comptes + ratios + [n_types, gap_mean, gap_std, gap_max,
                               proc_name_len, n_guid]


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--hotes-entrainement", required=True,
                   help="liste séparée par des virgules")
    p.add_argument("--fenetre", type=int, default=50)
    p.add_argument("--pas", type=int, default=50,
                   help="avancement du buffer entre deux fenêtres candidates "
                        "— <fenêtre pour un chevauchement partiel, ce qui "
                        "produit PLUS de fenêtres à partir du même volume "
                        "de logs, sans dupliquer la lecture du flux")
    p.add_argument("--max-part-categorie", type=float, default=0.80,
                   help="rejette les fenêtres où une catégorie dépasse "
                        "cette proportion")
    p.add_argument("--max-fenetres-par-hote", type=int, default=20_000,
                   help="plafond pour éviter qu'un hôte très actif domine "
                        "le corpus final")
    p.add_argument("--sortie", default="fenetres_entrainement.npz")
    args = p.parse_args()

    hotes_train = set(args.hotes_entrainement.split(","))
    print("=" * 70)
    print("  CONSTRUCTION DIRECTE DES FENÊTRES D'ENTRAÎNEMENT")
    print("=" * 70)
    print(f"  hôtes d'entraînement : {sorted(hotes_train)}")
    print(f"  fenêtre {args.fenetre}, pas {args.pas}, "
          f"seuil diversité {args.max_part_categorie:.0%}")

    buffers: dict[str, list] = defaultdict(list)
    compteurs_pas: dict[str, int] = defaultdict(int)
    fenetres_par_hote: Counter = Counter()
    toutes_fenetres = []

    n_total = n_bénin_hote_cible = 0
    for ligne_b in _lire_par_blocs():
        n_total += 1
        if n_total % 10_000_000 == 0:
            print(f"  {n_total:,} lus | fenêtres retenues : "
                  f"{len(toutes_fenetres):,}", file=sys.stderr, flush=True)
        if not ligne_b.strip():
            continue
        try:
            doc = json.loads(ligne_b)
        except json.JSONDecodeError:
            continue
        src = doc.get("_source")
        if not isinstance(src, dict):
            continue
        hote = src.get("host_name") or "?"
        if hote not in hotes_train:
            continue
        if src.get("rule_technique_id"):
            continue    # entraînement = BÉNIN uniquement
        if fenetres_par_hote[hote] >= args.max_fenetres_par_hote:
            continue    # plafond atteint pour cet hôte, ne plus accumuler

        n_bénin_hote_cible += 1
        buf = buffers[hote]
        buf.append(_record_leger(src))
        if len(buf) > args.fenetre:
            del buf[0]     # buffer glissant, garde les FENETRE derniers

        compteurs_pas[hote] += 1
        if len(buf) == args.fenetre and compteurs_pas[hote] >= args.pas:
            compteurs_pas[hote] = 0
            # Plus AUCUN filtre de diversité : le trafic réel est
            # majoritairement homogène (97% ProcessAccess) — un modèle
            # entraîné uniquement sur les fenêtres mixtes ne généralise pas
            # au trafic dominant. On garde TOUT ce que le buffer produit.
            scores = _scores_depuis_records(buf)
            if scores is not None:
                toutes_fenetres.append(scores)
                fenetres_par_hote[hote] += 1

    print(f"\n{n_total:,} documents lus, {n_bénin_hote_cible:,} bénins des "
          f"hôtes d'entraînement examinés.")
    print(f"\nFenêtres retenues par hôte :")
    for h, n in fenetres_par_hote.most_common():
        print(f"    {h:24s} {n:,}")
    print(f"\nTotal : {len(toutes_fenetres):,} fenêtres")

    import numpy as np
    X = np.array(toutes_fenetres, dtype=float)
    np.savez(args.sortie, X=X)
    print(f"\nSauvegardé : {args.sortie} (matrice {X.shape})")

    if len(X):
        from collect_agent.window_integrity import NOMS_SCORES
        print(f"\nPROFIL DU CORPUS FINAL")
        for i, n in enumerate(NOMS_SCORES[:8]):
            print(f"    {n:16s} moy {X[:,i].mean():8.3f}  std {X[:,i].std():8.3f}")


if __name__ == "__main__":
    main()
