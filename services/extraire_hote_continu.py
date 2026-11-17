"""
=============================================================================
EXTRACTION CONTINUE D'UN HÔTE — pour des record_number consécutifs
=============================================================================
⚠️ POURQUOI CE SCRIPT EXISTE
    `comiset_travail_v2.csv` contient bien `record_number`, mais il est
    SOUS-ÉCHANTILLONNÉ à 5 % du bénin. Conséquence mesurée dans E3 :
    `RecordGapDetector` signale un trou à CHAQUE log (12 589 déclenchements
    pour 451 justes, précision 0.036) — parce qu'en gardant 1 log sur 20,
    les numéros d'enregistrement ne se suivent jamais.

    Le détecteur faisait son travail correctement : il détectait de vrais
    trous. Mais ces trous venaient de l'échantillonnage, pas d'une
    falsification.

    Pour mesurer honnêtement la détection de suppression, il faut des logs
    CONSÉCUTIFS : tous les logs d'un hôte, dans l'ordre, sans aucun tri.
    Les seuls trous de `record_number` seront alors ceux réellement injectés
    par le générateur de falsification.

⚠️ UN SEUL HÔTE, PAS PLUSIEURS
    `RecordGapDetector` suit les numéros PAR SOURCE (`host:provider`).
    Mélanger plusieurs hôtes dans un même fichier n'invaliderait pas la
    mesure — le détecteur les sépare — mais un seul hôte donne un jeu plus
    simple à interpréter, sans entrelacement de séquences.

⚠️ AUCUN SOUS-ÉCHANTILLONNAGE, NI DU BÉNIN NI DES ATTAQUES
    C'est tout l'objet du script. Le volume est borné par --max-logs, en
    prenant les N PREMIERS logs de l'hôte dans l'ordre du flux — pas un
    tirage aléatoire qui recréerait le problème.

USAGE
    # 1. voir quels hôtes existent et leur volume
    unzip -p Comiset23_Lab_Environment_Dataset.zip dataset_comillas2.json \
      | python3 services/extraire_hote_continu.py --lister

    # 2. extraire un hôte précis, en continu
    unzip -p Comiset23_Lab_Environment_Dataset.zip dataset_comillas2.json \
      | python3 services/extraire_hote_continu.py \
        --hote desktop-4pvps6e.phoenix.local --max-logs 50000 \
        --sortie lab_continu.csv
=============================================================================
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter

_COLONNES = [
    "@timestamp", "event_original_time", "host_name", "process_guid",
    "process_name", "process_path", "event_id", "task",
    "target_process_guid", "target_process_name", "TargetObject",
    "user_name", "src_ip_addr", "command_line",
    "rule_technique_id", "rule_technique_name", "record_number",
]


def _lire_par_blocs(taille_bloc: int = 64 * 1024 * 1024):
    """Lecture par blocs binaires — voir reextraire_lab_avec_record.py pour
    la justification (itération ligne par ligne ~100x plus lente sous Git
    Bash/MSYS2)."""
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
        "record_number": src.get("record_number")
                         if src.get("record_number") is not None else "",
    }


def lister() -> None:
    """Volume et couverture de record_number par hôte — pour choisir lequel
    extraire en connaissance de cause."""
    volumes = Counter()
    avec_record = Counter()
    par_provider = Counter()
    n = 0
    for ligne_b in _lire_par_blocs():
        n += 1
        if n % 10_000_000 == 0:
            print(f"  {n:,} lus…", file=sys.stderr, flush=True)
        if not ligne_b.strip():
            continue
        try:
            doc = json.loads(ligne_b)
        except json.JSONDecodeError:
            continue
        src = doc.get("_source")
        if not isinstance(src, dict):
            continue
        h = src.get("host_name") or "?"
        volumes[h] += 1
        if src.get("record_number") is not None:
            avec_record[h] += 1
            par_provider[(h, src.get("source_name") or "?")] += 1

    print(f"\n{n:,} documents lus\n")
    print(f"{'hôte':40s} {'total':>12s} {'avec record':>12s} {'%':>7s}")
    print("-" * 74)
    for h, v in volumes.most_common():
        a = avec_record.get(h, 0)
        print(f"{h:40s} {v:>12,} {a:>12,} {a/v:>6.1%}")

    print(f"\n⚠️ `RecordGapDetector` suit les numéros par (hôte, provider).")
    print(f"   Providers principaux par hôte (top 8) :")
    for (h, p), v in par_provider.most_common(8):
        print(f"     {h:34s} {p:36s} {v:>10,}")


def extraire(hote: str, max_logs: int, sortie: str,
             provider: str | None = None, trier: bool = True,
             plafond_lecture: int = 2_000_000) -> None:
    """
    ⚠️ TRI PAR record_number OBLIGATOIRE (--pas-de-tri pour désactiver)
        Le fichier source est un export Elasticsearch : l'ordre des documents
        est celui de l'INDEXATION, pas celui de l'émission. Mesuré sans tri
        sur desktop-4pvps6e : seulement 22,9 % de record_number consécutifs,
        avec 9 243 RECULS — des numéros qui diminuent d'un log au suivant.

        Or Windows attribue les record_number séquentiellement à l'émission :
        le vrai ordre chronologique du journal EST celui des record_number.
        Trier dessus ne fabrique donc rien — cela RESTAURE l'ordre d'origine
        que l'export avait perdu.
    """
    n_total = n_attaques = n_sans_record = 0
    lignes_gardees = []
    try:
        for ligne_b in _lire_par_blocs():
            n_total += 1
            if n_total % 10_000_000 == 0:
                print(f"  {n_total:,} lus | retenus {len(lignes_gardees):,}",
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
            if (src.get("host_name") or "") != hote:
                continue
            if provider and (src.get("source_name") or "") != provider:
                continue

            # ⚠️ NE PAS s'arrêter aux N PREMIERS logs rencontrés.
            #    L'export étant désordonné, les N premiers sont dispersés sur
            #    toute la plage de numérotation : mesuré, 50 000 logs
            #    s'étalaient sur 2 199 966 numéros — une densité de 2,3 %.
            #    Trier ne comble pas ces trous ; il faut lire LARGEMENT
            #    puis découper une TRANCHE CONTIGUË (voir plus bas).
            #
            #    ⚠️ La lecture est PLAFONNÉE : tout garder en mémoire pour
            #    cet hôte (49,45 M logs) demanderait ~20 Go de RAM. Le
            #    plafond par défaut (2 M logs) suffit largement à contenir
            #    une zone dense de quelques dizaines de milliers d'entrées.
            lignes_gardees.append(_ligne_csv(src))
            if len(lignes_gardees) >= plafond_lecture:
                print(f"  plafond de lecture atteint "
                      f"({plafond_lecture:,} logs)", file=sys.stderr)
                break
    except (KeyboardInterrupt, BrokenPipeError, OSError) as e:
        print(f"\n  interrompu : {e}", file=sys.stderr)

    # --- tri par record_number : restaure l'ordre d'émission -------------
    if trier:
        def _cle(l):
            try:
                return (0, int(l["record_number"]))
            except (TypeError, ValueError):
                return (1, 0)      # sans numéro → rejeté en fin
        lignes_gardees.sort(key=_cle)
        print(f"\n  trié par record_number ({len(lignes_gardees):,} logs)",
              file=sys.stderr)

    # --- découpe de la TRANCHE la plus dense de max_logs entrées ---------
    #     On cherche la fenêtre de `max_logs` logs consécutifs (après tri)
    #     dont l'étendue de numérotation est la PLUS FAIBLE — c'est-à-dire
    #     la zone du journal la mieux couverte par l'extraction.
    if len(lignes_gardees) > max_logs:
        nums = []
        for l in lignes_gardees:
            try:
                nums.append(int(l["record_number"]))
            except (TypeError, ValueError):
                nums.append(None)
        meilleur_debut, meilleure_etendue = 0, None
        for i in range(0, len(nums) - max_logs + 1, max(1, max_logs // 20)):
            a, b = nums[i], nums[i + max_logs - 1]
            if a is None or b is None:
                continue
            etendue = b - a
            if meilleure_etendue is None or etendue < meilleure_etendue:
                meilleure_etendue, meilleur_debut = etendue, i
        lignes_gardees = lignes_gardees[meilleur_debut:meilleur_debut + max_logs]
        print(f"  tranche la plus dense retenue : logs "
              f"{meilleur_debut:,}–{meilleur_debut + max_logs:,} "
              f"(étendue {meilleure_etendue:,} numéros)", file=sys.stderr)

    n_attaques = sum(1 for l in lignes_gardees if l["rule_technique_id"])

    with open(sortie, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=_COLONNES)
        w.writeheader()
        for l in lignes_gardees:
            w.writerow(l)

    records = []
    for l in lignes_gardees:
        rn = l["record_number"]
        if rn == "":
            n_sans_record += 1
        else:
            try:
                records.append(int(rn))
            except (TypeError, ValueError):
                n_sans_record += 1

    n_ecrits = len(lignes_gardees)
    print(f"\n{n_total:,} documents lus", file=sys.stderr)
    print(f"  écrits : {n_ecrits:,} ({n_attaques:,} attaques)", file=sys.stderr)
    print(f"  sans record_number : {n_sans_record:,}", file=sys.stderr)

    # --- vérification DÉCISIVE : les record_number se suivent-ils ? -------
    if len(records) > 1:
        sauts = sum(1 for i in range(1, len(records))
                    if records[i] - records[i - 1] > 1)
        reculs = sum(1 for i in range(1, len(records))
                     if records[i] < records[i - 1])
        consecutifs = len(records) - 1 - sauts - reculs
        print(f"\n  CONTINUITÉ DES record_number ({len(records):,} valeurs)",
              file=sys.stderr)
        print(f"    consécutifs (+1)  : {consecutifs:,} "
              f"({consecutifs/(len(records)-1):.1%})", file=sys.stderr)
        print(f"    sauts (>+1)       : {sauts:,}", file=sys.stderr)
        print(f"    reculs (<0)       : {reculs:,}", file=sys.stderr)
        if consecutifs / (len(records) - 1) < 0.8:
            print(f"\n    ⚠️ MOINS DE 80 % DE CONSÉCUTIFS — le fichier ne "
                  f"convient PAS", file=sys.stderr)
            print(f"       à la mesure de suppression : RecordGapDetector "
                  f"signalera", file=sys.stderr)
            print(f"       ces sauts naturels comme des trous. Cause probable :",
                  file=sys.stderr)
            print(f"       plusieurs providers entrelacés sur cet hôte — "
                  f"relancer avec", file=sys.stderr)
            print(f"       --provider pour n'en garder qu'un seul.",
                  file=sys.stderr)
        else:
            print(f"\n    ✓ Continuité suffisante : les trous détectés par "
                  f"E3 seront", file=sys.stderr)
            print(f"      ceux injectés par le générateur, pas des artefacts.",
                  file=sys.stderr)
    print(f"\n  sortie : {sortie}", file=sys.stderr)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--lister", action="store_true",
                   help="afficher les hôtes et la couverture record_number")
    p.add_argument("--hote", help="hôte à extraire")
    p.add_argument("--provider", default=None,
                   help="ne garder qu'un provider (source_name) — utile si "
                        "les record_number de plusieurs providers "
                        "s'entrelacent sur le même hôte")
    p.add_argument("--max-logs", type=int, default=50_000)
    p.add_argument("--plafond-lecture", type=int, default=2_000_000,
                   help="nombre max de logs chargés en mémoire avant "
                        "découpe de la tranche dense (2M ≈ 800 Mo de RAM)")
    p.add_argument("--pas-de-tri", action="store_true",
                   help="ne PAS trier par record_number — à n'utiliser que "
                        "pour vérifier l'ordre brut de l'export")
    p.add_argument("--sortie", default="lab_continu.csv")
    args = p.parse_args()

    if args.lister:
        lister()
        return
    if not args.hote:
        print("  --hote requis (ou --lister pour voir les hôtes disponibles)")
        sys.exit(1)
    extraire(args.hote, args.max_logs, args.sortie, args.provider,
             trier=not args.pas_de_tri,
             plafond_lecture=args.plafond_lecture)


if __name__ == "__main__":
    main()
