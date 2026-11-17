"""
=============================================================================
DÉCOUPAGE TEMPOREL PAR MACHINE — généralisation intra-hôte
=============================================================================
⚠️ CE QUE CE SCRIPT MESURE, DIFFÉREMMENT DU DÉCOUPAGE PAR HÔTE
    Le découpage précédent (construire_fenetres_entrainement.py) sépare des
    MACHINES ENTIÈRES entre entraînement et test : 8 hôtes pour apprendre,
    5 jamais vus. Résultat mesuré : échec total (100% de suspicion), un vrai
    problème de généralisation INTER-machines.

    Ici, CHAQUE machine contribue aux DEUX jeux : ses fenêtres les plus
    ANCIENNES vont à l'entraînement, ses fenêtres les plus RÉCENTES vont au
    test. On mesure donc la généralisation DANS LE TEMPS sur une même
    machine — une question plus facile, et différente de la précédente.

    Si ce découpage réussit là où l'autre échouait totalement, cela confirme
    que le problème n'est pas la méthode (fenêtres + autoencodeur) mais bien
    la DIVERSITÉ INTER-MACHINES : chaque machine est stable dans le temps,
    mais différente des autres.

MÉTHODE
    Pour chaque hôte, un buffer glissant chronologique comme dans le script
    précédent — mais on répartit les fenêtres retenues 70% entraînement /
    30% test SELON LEUR ORDRE D'APPARITION (les premières en entraînement,
    les dernières en test), pas au hasard. Cela évite qu'une fenêtre de test
    soit temporellement adjacente (voire partiellement chevauchante) à une
    fenêtre d'entraînement, ce qui fuiterait de l'information.

    ⚠️ TOUS LES HÔTES DISPONIBLES SONT UTILISÉS (13, entraînement + test
    confondus dans Real Environment) — puisqu'on ne cherche plus à réserver
    des machines entières comme "jamais vues".

USAGE
    unzip -p Comiset23_Real_Environment_Dataset.zip Comiset23_Real_Environment_Dataset.json \
      | python3 services/construire_fenetres_temporel.py \
        --hotes computer01.domain.es,computer02.domain.es,... \
        --sortie-train fenetres_temporel_train.npz \
        --sortie-test fenetres_temporel_test.npz
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
    """Lecture par blocs binaires — voir construire_fenetres_entrainement.py
    pour la justification (itération ligne par ligne ~100x plus lente sous
    Git Bash/MSYS2)."""
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
    """Identique à construire_fenetres_entrainement.py — même calcul, pour
    rester strictement compatible avec le modèle chargé en production."""
    from collect_agent.window_integrity import categorie, CATEGORIES

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
    p.add_argument("--hotes", required=True,
                   help="liste séparée par des virgules — TOUS les hôtes à "
                        "utiliser, chacun contribuant aux deux jeux")
    p.add_argument("--fenetre", type=int, default=50)
    p.add_argument("--pas", type=int, default=50,
                   help="avancement du buffer — 50 (pas de chevauchement) "
                        "pour éviter toute fuite entre fenêtres adjacentes "
                        "de part et d'autre de la coupure train/test")
    p.add_argument("--ratio-train", type=float, default=0.70,
                   help="proportion des fenêtres de CHAQUE hôte allant à "
                        "l'entraînement — les plus ANCIENNES (ordre "
                        "chronologique), le reste va au test")
    p.add_argument("--max-fenetres-par-hote", type=int, default=20_000,
                   help="plafond total (train+test) par hôte")
    p.add_argument("--sortie-train", default="fenetres_temporel_train.npz")
    p.add_argument("--sortie-test", default="fenetres_temporel_test.npz")
    args = p.parse_args()

    hotes = set(args.hotes.split(","))
    print("=" * 70)
    print("  DÉCOUPAGE TEMPOREL PAR MACHINE — chaque hôte dans les deux jeux")
    print("=" * 70)
    print(f"  hôtes : {sorted(hotes)}")
    print(f"  fenêtre {args.fenetre}, pas {args.pas}, "
          f"ratio train {args.ratio_train:.0%} (par ordre chronologique)")

    # ⚠️ TOUTES les fenêtres candidates sont d'abord accumulées PAR HÔTE,
    #    dans l'ordre chronologique naturel du flux. La coupure train/test
    #    n'est décidée qu'À LA FIN, une fois qu'on connaît le nombre total
    #    de fenêtres de chaque hôte — impossible de savoir à l'avance à
    #    quel index la coupure des 70% tombera.
    fenetres_candidates: dict[str, list] = defaultdict(list)
    buffers: dict[str, list] = defaultdict(list)
    compteurs_pas: dict[str, int] = defaultdict(int)

    n_total = n_bénin_hote_cible = 0
    for ligne_b in _lire_par_blocs():
        n_total += 1
        if n_total % 10_000_000 == 0:
            n_cand = sum(len(v) for v in fenetres_candidates.values())
            print(f"  {n_total:,} lus | fenêtres candidates : {n_cand:,}",
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
        hote = src.get("host_name") or "?"
        if hote not in hotes:
            continue
        if src.get("rule_technique_id"):
            continue    # bénin uniquement, comme pour l'entraînement original
        if len(fenetres_candidates[hote]) >= args.max_fenetres_par_hote:
            continue

        n_bénin_hote_cible += 1
        buf = buffers[hote]
        buf.append(_record_leger(src))
        if len(buf) > args.fenetre:
            del buf[0]

        compteurs_pas[hote] += 1
        if len(buf) == args.fenetre and compteurs_pas[hote] >= args.pas:
            compteurs_pas[hote] = 0
            scores = _scores_depuis_records(list(buf))
            if scores is not None:
                fenetres_candidates[hote].append(scores)

    print(f"\n{n_total:,} documents lus, {n_bénin_hote_cible:,} bénins "
          f"examinés.")

    # --- coupure chronologique par hôte, à 70/30 -------------------------
    import numpy as np
    X_train, X_test = [], []
    print(f"\nRépartition par hôte (chronologique, {args.ratio_train:.0%} "
          f"ancien → train) :")
    for hote in sorted(fenetres_candidates):
        fens = fenetres_candidates[hote]
        n = len(fens)
        coupure = int(n * args.ratio_train)
        train_h, test_h = fens[:coupure], fens[coupure:]
        X_train.extend(train_h)
        X_test.extend(test_h)
        print(f"    {hote:24s} {n:>6,} fenêtres → "
              f"train {len(train_h):>5,} | test {len(test_h):>5,}")

    X_train = np.array(X_train, dtype=float)
    X_test = np.array(X_test, dtype=float)
    print(f"\nTotal : train {X_train.shape[0]:,} | test {X_test.shape[0]:,}")

    np.savez(args.sortie_train, X=X_train)
    np.savez(args.sortie_test, X=X_test)
    print(f"\nSauvegardés : {args.sortie_train}, {args.sortie_test}")

    if len(X_train):
        from collect_agent.window_integrity import NOMS_SCORES
        print(f"\nPROFIL TRAIN (8 premières features)")
        for i, n in enumerate(NOMS_SCORES[:8]):
            print(f"    {n:16s} moy {X_train[:,i].mean():8.3f}  "
                  f"std {X_train[:,i].std():8.3f}")
    if len(X_test):
        print(f"\nPROFIL TEST (8 premières features)")
        for i, n in enumerate(NOMS_SCORES[:8]):
            print(f"    {n:16s} moy {X_test[:,i].mean():8.3f}  "
                  f"std {X_test[:,i].std():8.3f}")


if __name__ == "__main__":
    main()
