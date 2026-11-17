"""
=============================================================================
EXTRACTION POUR RÉENTRAÎNEMENT — Real Environment, découpage par hôte
=============================================================================
Prépare deux jeux de données STRICTEMENT SÉPARÉS, sans lesquels aucune mesure
d'amélioration ne serait crédible :

    ENTRAÎNEMENT  logs bénins de certains hôtes, servent à réapprendre
                  le profil normal de l'autoencodeur
    TEST          logs (bénins ET malveillants) d'AUTRES hôtes, jamais
                  vus à l'entraînement — seule mesure valable de progrès

⚠️ POURQUOI LE DÉCOUPAGE EST PAR HÔTE, PAS PAR LIGNE AU HASARD
    Un découpage aléatoire mélangerait des logs du même hôte, de la même
    session, du même processus entre les deux jeux. Le modèle reconnaîtrait
    alors des habitudes déjà vues — pas de la généralisation, une fuite.
    Deux machines physiques distinctes n'ont aucun lien de ce type.

CE QUE CE SCRIPT FAIT, EN UN SEUL PASSAGE SUR LE FLUX
    1. Compte le volume par hôte (nécessaire pour équilibrer le découpage)
    2. Une fois le volume connu, répartit les hôtes en deux groupes
       équilibrés en NOMBRE D'ÉVÉNEMENTS (pas juste en nombre d'hôtes,
       un hôte peut produire dix fois plus qu'un autre)
    3. Écrit deux fichiers CSV, au format attendu par les scripts existants
       (mêmes colonnes que comiset_travail.csv), avec un sous-échantillonnage
       du bénin pour rester gérable en mémoire

⚠️ DEUX PASSAGES NÉCESSAIRES
    Le volume par hôte n'est connu qu'après avoir tout lu une fois — on ne
    peut pas décider du découpage AVANT de savoir combien chaque hôte pèse.
    Ce script fait donc DEUX passages : le premier compte, le second extrait
    selon la répartition décidée. Sur 934 Go, cela double le temps total —
    c'est le prix d'un découpage propre plutôt qu'un choix arbitraire.

USAGE
    # passage 1 : uniquement compter, rapide, écrit volume_par_hote.json
    unzip -p Comiset23_Real_Environment_Dataset.zip *.json \
      | python3 compter_hotes.py > volume_par_hote.json

    # décision du découpage (affichée automatiquement, ajustable)

    # passage 2 : extraction selon le découpage
    unzip -p Comiset23_Real_Environment_Dataset.zip *.json \
      | python3 extraire_reentrainement.py --volume volume_par_hote.json \
        --taux-benin 0.02
=============================================================================
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter


# =============================================================================
# PASSAGE 1 — compter le volume par hôte (rapide, un seul compteur)
# =============================================================================
def compter() -> None:
    """
    ⚠️ LECTURE PAR BLOCS BINAIRES, PAS `for ligne in sys.stdin`
        Sous Git Bash / MSYS2 (Windows), itérer un pipe ligne par ligne via
        `sys.stdin` peut être extrêmement lent — chaque lecture traverse une
        couche de traduction de fins de ligne coûteuse. Mesuré : la
        décompression seule fait 140-300 Mo/s, mais le comptage ligne par
        ligne plafonnait à ~1,7 Mo/s (30M lignes en 5h). La lecture par gros
        blocs sur `sys.stdin.buffer` (binaire, sans traduction) restaure le
        débit de décompression.
    """
    import sys as _sys
    volumes = Counter()
    volumes_attaque = Counter()
    n_total = 0
    reste = b""
    flux = _sys.stdin.buffer
    TAILLE_BLOC = 64 * 1024 * 1024   # 64 Mo par lecture

    while True:
        bloc = flux.read(TAILLE_BLOC)
        if not bloc:
            break
        bloc = reste + bloc
        lignes = bloc.split(b"\n")
        reste = lignes.pop()   # dernière ligne potentiellement incomplète

        for ligne_b in lignes:
            n_total += 1
            if n_total % 5_000_000 == 0:
                print(f"  {n_total:,} lus…", file=sys.stderr, flush=True)
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
            volumes[hote] += 1
            if src.get("rule_technique_id"):
                volumes_attaque[hote] += 1

    if reste.strip():
        n_total += 1
        try:
            doc = json.loads(reste)
            src = doc.get("_source")
            if isinstance(src, dict):
                hote = src.get("host_name") or "?"
                volumes[hote] += 1
                if src.get("rule_technique_id"):
                    volumes_attaque[hote] += 1
        except json.JSONDecodeError:
            pass

    resultat = {"total": n_total, "par_hote": dict(volumes.most_common()),
               "attaques_par_hote": dict(volumes_attaque.most_common())}
    json.dump(resultat, sys.stdout, ensure_ascii=False, indent=2)
    print(f"\n{n_total:,} lignes comptées.", file=sys.stderr)


def proposer_decoupage(volume_json: str) -> tuple[set, set]:
    """
    Découpage VALIDÉ manuellement sur le comptage complet des 202 304 794
    événements (voir volume_par_hote.json). Décisions prises avec l'humain :

      · computer11, computer12 EXCLUS : volume négligeable (700 et 600
        événements sur 202M — ni exploitable en entraînement ni en test).
      · desktop-mh88805 EXCLU : taux d'attaque de 6,47 %, vingt fois celui
        des autres hôtes (~0,3 %). Sur seulement 140 593 événements, ce
        déséquilibre est probablement un artefact de collecte partielle ou
        une machine traitée différemment — le mélanger fausserait le
        découpage plutôt que de l'enrichir.
      · TEST : 5 hôtes de tailles variées (un gros + quatre moyens), plutôt
        que les deux plus gros seuls — un test sur 2 machines physiques
        serait fragile à un biais propre à l'une d'elles.

    Résultat : 67,5 % / 32,5 % en volume ET en attaques (202 192 événements
    d'attaque en test, largement suffisant pour un rappel fiable) — le ratio
    identique sur les deux confirme l'absence de biais systématique introduit
    par le découpage.
    """
    with open(volume_json, encoding="utf-8") as f:
        d = json.load(f)

    exclus = {"computer11.domain.es", "computer12.domain.es", "desktop-mh88805"}
    test = {"computer04.domain.es", "computer13.domain.es",
            "computer08.domain.es", "computer09.domain.es",
            "computer05.domain.es"}
    entrainement = {h for h in d["par_hote"] if h not in exclus and h not in test}

    print("=" * 70, file=sys.stderr)
    print("  DÉCOUPAGE (validé manuellement sur le comptage complet)",
          file=sys.stderr)
    print("=" * 70, file=sys.stderr)
    print(f"\n  EXCLUS : {sorted(exclus)}", file=sys.stderr)
    print(f"\n  ENTRAÎNEMENT ({len(entrainement)} hôtes, "
          f"{sum(d['par_hote'][h] for h in entrainement):,} événements) :",
          file=sys.stderr)
    for h in sorted(entrainement):
        att = d["attaques_par_hote"].get(h, 0)
        print(f"    {h:24s} {d['par_hote'][h]:>12,} évts  ({att} attaques)",
              file=sys.stderr)
    print(f"\n  TEST ({len(test)} hôtes, "
          f"{sum(d['par_hote'][h] for h in test):,} événements) :",
          file=sys.stderr)
    for h in sorted(test):
        att = d["attaques_par_hote"].get(h, 0)
        print(f"    {h:24s} {d['par_hote'][h]:>12,} évts  ({att} attaques)",
              file=sys.stderr)
    print(file=sys.stderr)
    return entrainement, test


# =============================================================================
# PASSAGE 2 — extraire selon le découpage
# =============================================================================
_COLONNES = ["@timestamp", "event_original_time", "host_name", "process_guid",
            "process_name", "process_path", "event_id", "task",
            "target_process_guid", "target_process_name", "TargetObject",
            "user_name", "src_ip_addr", "command_line",
            "rule_technique_id", "rule_technique_name",
            # ⚠️ Ajoutés après lecture COMPLÈTE de l'article (section 4.3) :
            #    la filiation de processus est nécessaire pour la règle
            #    forensique R4 (self_parent) et pour un séquençage plus fin.
            #    Absents des premières versions du mapping, construites par
            #    inspection d'extraits plutôt que par la documentation.
            "process_parent_guid", "process_parent_id", "process_parent_name",
            "parent_user", "parent_command_line"]


def _ligne_csv(src: dict) -> dict:
    """Convertit un document Real vers le schéma de comiset_travail.csv."""
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
        # noms de champs tels que documentés en section 4.3 de l'article ;
        # la casse réelle dans le JSON peut différer (le pipeline Logstash
        # normalise en minuscules pour certains champs, pas tous), on
        # essaie donc plusieurs variantes
        "process_parent_guid": (src.get("process_parent_guid")
                                or src.get("Process_parent_guid") or ""),
        "process_parent_id": (src.get("process_parent_id")
                              or src.get("Process_parent_id") or ""),
        "process_parent_name": (src.get("process_parent_name")
                                or src.get("Process_parent_name") or ""),
        "parent_user": src.get("ParentUser") or src.get("parent_user") or "",
        "parent_command_line": (src.get("ParentCommandLine")
                                or src.get("parent_command_line") or ""),
    }


def _lire_par_blocs(taille_bloc: int = 64 * 1024 * 1024):
    """
    Générateur de lignes depuis sys.stdin.buffer, en gros blocs binaires.

    ⚠️ Ne PAS remplacer par `for ligne in sys.stdin` : sous Git Bash/MSYS2,
    l'itération ligne par ligne sur un pipe est ~100x plus lente que le débit
    de décompression réel (mesuré : 1,7 Mo/s au lieu de 140-300 Mo/s).
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


def extraire(entrainement: set, test: set, taux_benin: float,
            sortie_train: str, sortie_test: str,
            taux_benin_test: float = 0.05,
            sortie_train_attaques: str = "real_entrainement_attaques.csv") -> None:
    """
    ⚠️ LE BÉNIN DU JEU DE TEST EST AUSSI SOUS-ÉCHANTILLONNÉ.
        Garder TOUT le bénin de test (65,7 M événements sur 5 hôtes) produit
        un fichier de 45 à 55 Go — constaté : `OSError: No space left on
        device` après 145 M lignes lues. Un jeu de test n'a pas besoin
        d'être exhaustif pour être statistiquement valide : quelques
        centaines de milliers d'événements bénins suffisent largement à
        mesurer un FPR fiable.

        Les 202 192 événements d'ATTAQUE du jeu de test, eux, sont TOUJOURS
        intégralement conservés — ils sont rares et chacun compte pour la
        mesure du rappel.

    ⚠️ TROISIÈME FICHIER : LES ATTAQUES D'ENTRAÎNEMENT.
        Le détecteur Windows (RandomForest, contrairement à l'autoencodeur)
        a besoin d'exemples d'ATTAQUE pour apprendre, pas seulement de bénin.
        Les 8 hôtes d'entraînement portent 420 323 attaques — on les extrait
        ici, dans un fichier SÉPARÉ de `real_test.csv`, pour ne jamais
        toucher au jeu de test réservé à la mesure finale.
    """
    import csv
    import random
    rng = random.Random(42)

    f_train = open(sortie_train, "w", newline="", encoding="utf-8")
    f_test = open(sortie_test, "w", newline="", encoding="utf-8")
    f_train_att = open(sortie_train_attaques, "w", newline="", encoding="utf-8")
    w_train = csv.DictWriter(f_train, fieldnames=_COLONNES)
    w_test = csv.DictWriter(f_test, fieldnames=_COLONNES)
    w_train_att = csv.DictWriter(f_train_att, fieldnames=_COLONNES)
    w_train.writeheader()
    w_test.writeheader()
    w_train_att.writeheader()

    n_total = n_train = n_test = n_test_att = n_test_benin = n_train_att = 0
    try:
        for ligne_b in _lire_par_blocs():
            n_total += 1
            if n_total % 5_000_000 == 0:
                print(f"  {n_total:,} lus | train {n_train:,}+{n_train_att:,}att "
                      f"| test {n_test:,} (att {n_test_att:,} + "
                      f"bénin {n_test_benin:,})…", file=sys.stderr, flush=True)
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
            est_attaque = bool(src.get("rule_technique_id"))

            if hote in entrainement:
                if est_attaque:
                    # TOUJOURS conservée : rare, nécessaire au détecteur
                    w_train_att.writerow(_ligne_csv(src))
                    n_train_att += 1
                elif rng.random() < taux_benin:
                    w_train.writerow(_ligne_csv(src))
                    n_train += 1
            elif hote in test:
                if est_attaque:
                    w_test.writerow(_ligne_csv(src))
                    n_test += 1
                    n_test_att += 1
                elif rng.random() < taux_benin_test:
                    w_test.writerow(_ligne_csv(src))
                    n_test += 1
                    n_test_benin += 1
    except (KeyboardInterrupt, BrokenPipeError, OSError):
        print(f"\n  interrompu à {n_total:,} lignes — fichiers partiels "
              f"conservés.", file=sys.stderr)
    finally:
        f_train.close()
        f_test.close()
        f_train_att.close()

    print(f"\n{n_total:,} lignes lues :", file=sys.stderr)
    print(f"  entraînement bénin    : {n_train:,} → {sortie_train}",
          file=sys.stderr)
    print(f"  entraînement attaques : {n_train_att:,} → {sortie_train_attaques}",
          file=sys.stderr)
    print(f"  test                  : {n_test:,} ({n_test_att:,} attaques + "
          f"{n_test_benin:,} bénins) → {sortie_test}", file=sys.stderr)


# =============================================================================
def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--compter", action="store_true",
                   help="passage 1 : compter le volume par hôte")
    p.add_argument("--volume", help="passage 2 : fichier produit par --compter")
    p.add_argument("--taux-benin", type=float, default=0.02,
                   help="proportion du bénin d'entraînement conservée")
    p.add_argument("--taux-benin-test", type=float, default=0.05,
                   help="proportion du bénin de TEST conservée (les "
                        "attaques du test sont TOUJOURS toutes gardées)")
    p.add_argument("--sortie-train", default="real_entrainement.csv")
    p.add_argument("--sortie-train-attaques",
                   default="real_entrainement_attaques.csv",
                   help="attaques des hôtes d'entraînement — nécessaires au "
                        "détecteur Windows (RandomForest), pas à "
                        "l'autoencodeur")
    p.add_argument("--sortie-test", default="real_test.csv")
    args = p.parse_args()

    if args.compter:
        compter()
        return

    if not args.volume:
        print("  --volume requis pour l'extraction (résultat de --compter)")
        sys.exit(1)

    entrainement, test = proposer_decoupage(args.volume)
    extraire(entrainement, test, args.taux_benin,
            args.sortie_train, args.sortie_test, args.taux_benin_test,
            args.sortie_train_attaques)


if __name__ == "__main__":
    main()
