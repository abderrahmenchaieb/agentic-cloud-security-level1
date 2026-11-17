"""
=============================================================================
EXTRACTION DE CLASSES COMPARABLES — bénins et attaques du MÊME flux
=============================================================================
⚠️ LE DÉFAUT QUE CE SCRIPT CORRIGE
    `extraire_reentrainement.py` produisait DEUX fichiers par des traitements
    DIFFÉRENTS :

      real_entrainement.csv          bénin sous-échantillonné à 2 %
      real_entrainement_attaques.csv attaques conservées intégralement

    Un tirage aléatoire uniforme préserve la proportion du corpus source :
    le bénin est donc resté à 98,9 % d'EventID 10 (ProcessAccess), tandis que
    les attaques — conservées telles quelles — sont à 83,8 % d'EventID 7
    (ImageLoad, où T1055 est majoritairement étiqueté).

    Un détecteur entraîné sur ces deux fichiers n'apprend PAS à distinguer
    une attaque d'un comportement normal : il apprend à distinguer un
    chargement de DLL d'un accès processus. D'où un FPR de 0,001 — trivial à
    obtenir, et sans aucun rapport avec la détection d'intrusion.

MÉTHODE : L'UNITÉ D'EXTRACTION EST LE PROCESSUS, PAS LE LOG
    Le détecteur séquence par `(host, process_guid)`. On sélectionne donc des
    PROCESSUS entiers, et on garde TOUS leurs logs — qu'ils soient étiquetés
    ou non.

    Un processus est « attaque » s'il porte au moins un log étiqueté. Les
    deux classes subissent alors exactement le même traitement : aucun
    sous-échantillonnage interne, aucun filtre par type d'événement. La seule
    différence entre elles est l'étiquette, ce qui est précisément ce que le
    modèle doit apprendre.

⚠️ POURQUOI DEUX PASSAGES
    On ne sait qu'un processus est « attaque » qu'après avoir vu TOUS ses
    logs — l'étiquette peut apparaître au dernier. Le premier passage
    identifie donc les process_guid concernés, le second extrait leurs logs.

USAGE
    # passage 1 : repérer les processus attaqués
    unzip -p Comiset23_Real_Environment_Dataset.zip Comiset23_Real_Environment_Dataset.json \
      | python3 services/extraire_classes_comparables.py --reperer \
        --hotes computer01.domain.es,... > guids_attaque.json

    # passage 2 : extraire les logs des deux classes
    unzip -p Comiset23_Real_Environment_Dataset.zip Comiset23_Real_Environment_Dataset.json \
      | python3 services/extraire_classes_comparables.py \
        --guids guids_attaque.json --hotes computer01.domain.es,... \
        --sortie real_comparable.csv
=============================================================================
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import sys
from collections import Counter, defaultdict

_COLONNES = [
    "@timestamp", "event_original_time", "host_name", "process_guid",
    "process_name", "process_path", "event_id", "task",
    "target_process_guid", "target_process_name", "TargetObject",
    "user_name", "src_ip_addr", "command_line",
    "rule_technique_id", "rule_technique_name", "record_number",
]


def _lire_par_blocs(taille_bloc: int = 64 * 1024 * 1024):
    """Lecture par blocs binaires — l'itération ligne par ligne sur un pipe
    est ~100x plus lente sous Git Bash/MSYS2."""
    reste = b""
    flux = sys.stdin.buffer
    while True:
        bloc = flux.read(taille_bloc)
        if not bloc:
            break
        bloc = reste + bloc
        lignes = bloc.split(b"\n")
        reste = lignes.pop()
        for l in lignes:
            yield l
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
        "record_number": src.get("record_number")
                         if src.get("record_number") is not None else "",
    }


# =============================================================================
def reperer(hotes: set) -> None:
    """
    Passage 1 — quels process_guid portent au moins un log étiqueté ?

    On relève aussi le nombre de logs par processus, pour pouvoir écarter au
    passage 2 les processus trop courts (moins de 3 logs ne forment pas une
    séquence exploitable).
    """
    attaque = set()
    volume = Counter()
    n = 0
    for ligne_b in _lire_par_blocs():
        n += 1
        if n % 20_000_000 == 0:
            print(f"  {n:,} lus | {len(attaque):,} processus attaqués",
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
        if (src.get("host_name") or "") not in hotes:
            continue
        guid = (src.get("process_guid") or "").strip()
        if not guid:
            continue
        volume[guid] += 1
        if src.get("rule_technique_id"):
            attaque.add(guid)

    json.dump({"guids_attaque": sorted(attaque),
               "volume_par_guid": dict(volume)},
              sys.stdout)
    print(f"\n{n:,} documents lus", file=sys.stderr)
    print(f"  {len(volume):,} processus distincts", file=sys.stderr)
    print(f"  {len(attaque):,} portant au moins un log étiqueté "
          f"({len(attaque)/max(1,len(volume)):.2%})", file=sys.stderr)


def extraire(hotes: set, chemin_guids: str, sortie: str,
             max_processus_benins: int, min_logs: int, seed: int) -> None:
    """
    Passage 2 — tous les logs des processus sélectionnés, sans distinction
    de traitement entre les deux classes.
    """
    with open(chemin_guids, encoding="utf-8") as f:
        d = json.load(f)
    guids_att = set(d["guids_attaque"])
    volume = d.get("volume_par_guid", {})

    # ⚠️ APPARIEMENT PAR TAILLE — indispensable.
    #    Limiter le NOMBRE de processus bénins sans regarder leur TAILLE
    #    laisse le tirage attraper des processus système très actifs.
    #    Mesuré : 20 000 processus bénins → 134,2 M logs (6 710 logs chacun)
    #    contre 72 132 processus attaqués → 0,4 M logs (5,3 logs chacun),
    #    soit un facteur 1 250. Le modèle apprendrait alors la TAILLE des
    #    séquences, pas leur contenu — et le fichier produit serait
    #    ingérable (134 M lignes).
    #
    #    On sélectionne donc des processus bénins dont la taille se situe
    #    dans la même plage que celle des processus attaqués.
    # ⚠️ APPARIEMENT INDIVIDUEL, PAS PAR PLAGE GLOBALE.
    #    Filtrer les deux classes sur un même intervalle laisse subsister un
    #    écart important quand la distribution est très étalée : mesuré,
    #    facteur 6 même après restriction à l'interquartile.
    #    Pour CHAQUE processus attaqué, on choisit donc UN processus bénin
    #    de taille la plus proche possible, puis on le retire du vivier.
    #    Les deux classes ont alors, par construction, la même distribution
    #    de tailles — l'écart ne peut plus rien expliquer.
    import bisect

    rng = random.Random(seed)
    att_eligibles = {g for g in guids_att if volume.get(g, 0) >= min_logs}
    if len(att_eligibles) > max_processus_benins:
        att_eligibles = set(rng.sample(sorted(att_eligibles),
                                       max_processus_benins))

    vivier = sorted(((volume.get(g, 0), g) for g in volume
                     if g not in guids_att and volume.get(g, 0) >= min_logs),
                    key=lambda t: t[0])
    tailles_vivier = [t for t, _ in vivier]

    benins_eligibles, apparies_att, ecarts = [], [], []
    for g in sorted(att_eligibles, key=lambda x: -volume.get(x, 0)):
        if not vivier:
            break
        cible = volume.get(g, 0)
        i = bisect.bisect_left(tailles_vivier, cible)
        meilleurs = [j for j in (i - 1, i) if 0 <= j < len(vivier)]
        if not meilleurs:
            break
        j = min(meilleurs, key=lambda x: abs(tailles_vivier[x] - cible))
        taille, guid = vivier[j]

        # ⚠️ REJETER LA PAIRE SI AUCUN BÉNIN COMPARABLE N'EXISTE.
        #    Prendre « le plus proche disponible » sans condition accepte des
        #    paires absurdes quand le vivier ne contient rien d'équivalent :
        #    mesuré, un processus attaqué de 5 000 logs apparié à un bénin de
        #    20, d'où un écart moyen resté à 31,8 malgré l'appariement.
        #    On exige un rapport de taille borné ; les processus attaqués
        #    sans contrepartie sont ÉCARTÉS, pas appariés de force.
        rapport = max(taille, cible) / max(1, min(taille, cible))
        if rapport > 2.0:
            continue

        vivier.pop(j)
        tailles_vivier.pop(j)
        benins_eligibles.append(guid)
        apparies_att.append(g)
        ecarts.append(abs(taille - cible))

    n_ecartes = len(att_eligibles) - len(apparies_att)
    if ecarts:
        print(f"  appariement individuel : {len(apparies_att):,} paires, "
              f"écart médian {sorted(ecarts)[len(ecarts)//2]} log(s)",
              file=sys.stderr)
    if n_ecartes:
        print(f"  {n_ecartes:,} processus attaqué(s) ÉCARTÉ(S) faute de "
              f"bénin de taille comparable", file=sys.stderr)
        print(f"     (rapport de taille toléré : 2,0)", file=sys.stderr)
    garde = set(benins_eligibles) | set(apparies_att)
    att_eligibles = set(apparies_att)

    print(f"  {len(att_eligibles):,} processus d'attaque, "
          f"{len(benins_eligibles):,} processus bénins retenus",
          file=sys.stderr)

    f_out = open(sortie, "w", newline="", encoding="utf-8")
    w = csv.DictWriter(f_out, fieldnames=_COLONNES)
    w.writeheader()

    n = n_ecrits = 0
    profils = {0: Counter(), 1: Counter()}
    volumes_classe = {0: 0, 1: 0}
    try:
        for ligne_b in _lire_par_blocs():
            n += 1
            if n % 20_000_000 == 0:
                print(f"  {n:,} lus | {n_ecrits:,} écrits",
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
            if (src.get("host_name") or "") not in hotes:
                continue
            guid = (src.get("process_guid") or "").strip()
            if guid not in garde:
                continue

            ligne = _ligne_csv(src)
            w.writerow(ligne)
            n_ecrits += 1
            classe = 1 if guid in guids_att else 0
            profils[classe][ligne["event_id"]] += 1
            volumes_classe[classe] += 1
    except (KeyboardInterrupt, BrokenPipeError, OSError) as e:
        print(f"\n  interrompu : {e}", file=sys.stderr)
    finally:
        f_out.close()

    print(f"\n{n:,} documents lus, {n_ecrits:,} écrits → {sortie}",
          file=sys.stderr)

    # --- vérification immédiate de comparabilité -------------------------
    tot = {c: sum(p.values()) or 1 for c, p in profils.items()}
    eids = set(profils[0]) | set(profils[1])
    divergence = 0.5 * sum(
        abs(profils[1][e] / tot[1] - profils[0][e] / tot[0]) for e in eids)
    # ⚠️ Contrôle de VOLUME — un déséquilibre de volume fait apprendre la
    #    taille des séquences plutôt que leur contenu.
    n_att_p = len(att_eligibles)
    n_ben_p = len(benins_eligibles)
    m_att = volumes_classe[1] / n_att_p if n_att_p else 0
    m_ben = volumes_classe[0] / n_ben_p if n_ben_p else 0
    print(f"\n  VOLUME PAR CLASSE", file=sys.stderr)
    print(f"    attaque : {n_att_p:,} processus, {volumes_classe[1]:,} logs "
          f"({m_att:.1f}/processus)", file=sys.stderr)
    print(f"    bénin   : {n_ben_p:,} processus, {volumes_classe[0]:,} logs "
          f"({m_ben:.1f}/processus)", file=sys.stderr)
    if m_att and m_ben:
        facteur = max(m_ben, m_att) / min(m_ben, m_att)
        print(f"    écart de taille moyenne : facteur {facteur:.1f}",
              file=sys.stderr)
        if facteur > 3:
            print(f"    ⚠️ Écart trop important : le modèle apprendrait la",
                  file=sys.stderr)
            print(f"       TAILLE des séquences, pas leur contenu.",
                  file=sys.stderr)

    print(f"\n  PROFILS D'EventID PAR CLASSE", file=sys.stderr)
    print(f"    {'EventID':>9s} {'bénin':>10s} {'attaque':>10s}",
          file=sys.stderr)
    communs = Counter({e: profils[0][e] + profils[1][e] for e in eids})
    for e, _ in communs.most_common(6):
        print(f"    {e:>9s} {profils[0][e]/tot[0]:>9.1%} "
              f"{profils[1][e]/tot[1]:>10.1%}", file=sys.stderr)
    print(f"\n    divergence : {divergence:.1%}", file=sys.stderr)
    if divergence > 0.30:
        print(f"    ⚠️ ENCORE TROP DIVERGENT — les classes ne sont pas",
              file=sys.stderr)
        print(f"       comparables malgré l'extraction commune. Les attaques",
              file=sys.stderr)
        print(f"       de ce corpus portent réellement sur d'autres types",
              file=sys.stderr)
        print(f"       d'événements : c'est un fait du dataset, à déclarer.",
              file=sys.stderr)
    else:
        print(f"    → classes comparables : un modèle entraîné dessus "
              f"apprendra", file=sys.stderr)
        print(f"      la différence attaque/bénin, pas la différence "
              f"d'extraction.", file=sys.stderr)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--reperer", action="store_true",
                   help="passage 1 : identifier les processus attaqués")
    p.add_argument("--hotes", required=True,
                   help="liste d'hôtes séparés par des virgules")
    p.add_argument("--guids", help="passage 2 : fichier produit par --reperer")
    p.add_argument("--sortie", default="real_comparable.csv")
    p.add_argument("--max-processus-benins", type=int, default=20_000)
    p.add_argument("--min-logs", type=int, default=3,
                   help="processus trop courts écartés (pas de séquence)")
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args()

    hotes = set(args.hotes.split(","))
    if args.reperer:
        reperer(hotes)
        return
    if not args.guids:
        print("  --guids requis (résultat de --reperer)")
        sys.exit(1)
    extraire(hotes, args.guids, args.sortie,
             args.max_processus_benins, args.min_logs, args.seed)


if __name__ == "__main__":
    main()
