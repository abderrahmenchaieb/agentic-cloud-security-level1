"""
=============================================================================
E2 — DÉTECTION DE MENACE (voie Windows)
=============================================================================
Que détecte le SYSTÈME COMPLET, sur des données à vérité terrain connue ?

⚠️ CE QUI DISTINGUE CETTE MESURE DE CELLE DU MODÈLE SEUL
    Les chiffres de référence (recall 0.906, precision 0.950) proviennent
    d'une validation croisée du RandomForest isolé :

        StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        cross_val_predict(rf, X, y, cv=cv)

    Ils mesurent le MODÈLE. E2 mesure le PIPELINE : les événements traversent
    Collect (règles forensiques, autoencodeur), sont séquencés par
    process_guid, leurs 18 features structurelles sont extraites, puis
    Analysis décide. Le séquençage, l'extraction et les seuils réels
    interviennent — autant d'étapes absentes de la validation croisée.

    Un écart entre les deux mesures n'est pas une contradiction : il indique
    ce que l'intégration coûte ou apporte.

⚠️ LIMITE À DÉCLARER SELON LE JEU UTILISÉ
    · comiset_travail.csv (Lab) : le détecteur a été ENTRAÎNÉ sur ce corpus.
      La mesure porte donc sur l'intégration, pas sur la généralisation.
      Les chiffres seront optimistes et doivent être présentés comme tels.

    · Comiset23 Real Environment : environnement JAMAIS VU. La mesure y est
      une vraie évaluation de généralisation — et probablement plus sévère.
      L'écart entre les deux est en soi un résultat : il quantifie la
      transférabilité, question ouverte de la littérature.

VÉRITÉ TERRAIN — convention établie à l'entraînement, reprise à l'identique
    is_attack = rule_technique_id renseigné (non vide, non "nan")
    Un événement sans étiquette est BÉNIN.

UNITÉ DE MESURE — la SÉQUENCE, pas l'événement
    Le détecteur classe des séquences (groupes d'événements partageant un
    process_guid), non des événements isolés. Une séquence est étiquetée
    « attaque » si elle contient au moins un événement étiqueté.

USAGE
    python3 E2_detection_menace.py --csv comiset_travail.csv
    python3 E2_detection_menace.py --csv comiset_real.csv --max 200000
=============================================================================
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from collections import Counter, defaultdict

_ICI = os.path.dirname(os.path.abspath(__file__))
_RACINE = os.path.dirname(_ICI)
for p in (_ICI, _RACINE,
          os.path.join(_RACINE, "agents", "1_collect_agent"),
          os.path.join(_RACINE, "agents", "2_analysis_agent")):
    if p not in sys.path:
        sys.path.insert(0, p)


# =============================================================================
# ⚠️ BIAIS D'ÉCHANTILLONNAGE DU CORPUS — À DÉCLARER AVEC TOUT RÉSULTAT
#
#    `comiset_travail.csv` a été extrait du dataset COMISET en conservant
#    TOUTES les attaques mais seulement 5 % du bénin (1,71 M contre 2,39 M
#    événements). Le ratio attaque/bénin y est donc artificiellement élevé.
#
#    Conséquence : le FPR mesuré ici SOUS-ESTIME celui d'un déploiement réel,
#    où le trafic bénin domine massivement. Un FPR de 0,05 sur ce corpus
#    correspondrait à bien davantage de fausses alertes en production.
#
# ⚠️ CE QUI EST MESURÉ N'EST PAS LA GÉNÉRALISATION
#
#    Le détecteur exporté a été réentraîné sur l'intégralité de ce corpus :
#    les données de test lui sont connues. Ces chiffres valent pour
#    l'INTÉGRATION du modèle dans le pipeline, pas pour sa performance sur un
#    environnement inédit — laquelle exige COMISET Real Environment.
#
#    La référence de généralisation reste la validation croisée à 5 plis
#    (StratifiedKFold, random_state=42) : recall 0.906, precision 0.950.


def est_attaque(ligne: dict) -> bool:
    """
    Convention d'étiquetage établie à l'entraînement — reprise TELLE QUELLE.

    La reformuler introduirait un écart entre ce sur quoi le modèle a appris
    et ce sur quoi on le mesure : l'erreur de labellisation qu'on avait
    commise côté cloud (`"stratus" in ua` au lieu de `startswith`) avait
    gonflé le rappel de 0.879 à 0.927.
    """
    v = str(ligne.get("rule_technique_id", "") or "").strip()
    return bool(v) and v.lower() != "nan"


def charger_sequences(chemin: str, max_lignes: int | None,
                      taille_min: int = 3) -> tuple[list, list, dict]:
    """
    Reconstruit les séquences telles que le système les verrait.

    Regroupement par (host, process_guid) — le même critère que
    SequenceBuilder. Une séquence trop courte n'est pas analysable :
    le détecteur travaille sur des ratios, qui n'ont pas de sens sur
    un ou deux événements.
    """
    groupes: dict = defaultdict(list)
    stats = Counter()

    with open(chemin, newline="", encoding="utf-8", errors="ignore") as f:
        for i, ligne in enumerate(csv.DictReader(f)):
            if max_lignes and i >= max_lignes:
                break
            stats["lus"] += 1
            guid = str(ligne.get("process_guid", "") or "").strip()
            hote = str(ligne.get("host_name", "") or "").strip() or "?"
            if not guid or guid.lower() == "nan":
                stats["sans_guid"] += 1
                continue
            # marquer chaque événement : l'étiquetage des sous-séquences
            # après découpage temporel en dépend
            ligne["_attaque"] = est_attaque(ligne)
            groupes[(hote, guid)].append(ligne)
            if ligne["_attaque"]:
                stats["evenements_attaque"] += 1

    sequences, etiquettes = [], []
    for cle, evts in groupes.items():
        if len(evts) < taille_min:
            stats["sequences_trop_courtes"] += 1
            continue
        sequences.append((cle, evts))
        etiquettes.append(1 if any(est_attaque(e) for e in evts) else 0)

    stats["sequences_retenues"] = len(sequences)
    stats["sequences_attaque"] = sum(etiquettes)
    stats["sequences_benignes"] = len(etiquettes) - sum(etiquettes)
    return sequences, etiquettes, dict(stats)


# =============================================================================
def convertir_en_events(evts: list[dict]):
    """
    Transforme des lignes COMISET en Event du séquenceur.

    On passe par le mapper Sysmon pour emprunter EXACTEMENT le chemin du
    système : reconstruire les Event à la main court-circuiterait le
    Collect, et la mesure ne porterait plus sur le pipeline réel.
    """
    from collect_agent.sysmon_mapper import map_sysmon_event
    from analysis_agent.windows_bridge import canonical_to_windows_events

    canoniques = []
    for e in evts:
        brut = {
            "EventID": str(e.get("event_id", "") or "").strip(),
            "UtcTime": str(e.get("@timestamp", "") or "").replace("T", " ")
                          .replace("Z", "").strip(),
            "Computer": e.get("host_name") or "?",
            "ProcessGuid": e.get("process_guid") or "",
            "Image": e.get("process_path") or e.get("process_name") or "",
        }
        cible = str(e.get("target_process_guid", "") or "").strip()
        if cible:
            brut["TargetProcessGuid"] = cible
            brut["TargetImage"] = e.get("target_process_name") or ""
        obj = str(e.get("TargetObject", "") or "").strip()
        if obj:
            brut["TargetObject"] = obj
        ip = str(e.get("src_ip_addr", "") or "").strip()
        if ip:
            brut["DestinationIp"] = ip
        cmd = str(e.get("command_line", "") or "").strip()
        if cmd:
            brut["CommandLine"] = cmd

        res = map_sysmon_event(brut)
        log = getattr(res, "log", None)
        if log is not None:
            canoniques.append(log)

    return canonical_to_windows_events(canoniques) if canoniques else []


def evaluer(sequences: list, etiquettes: list[int], seuil: float | None):
    """
    Fait passer chaque séquence dans le détecteur du système.

    ⚠️ L'ÉTIQUETTE SUIT LE DÉCOUPAGE RÉEL DU BUILDER
        `SequenceBuilder` redécoupe un groupe (host, process_guid) selon sa
        fenêtre temporelle : un même processus peut produire PLUSIEURS
        sous-séquences. Sur COMISET, 4 858 groupes en produisaient 10 099.

        Appliquer l'étiquette du groupe à toutes ses sous-séquences est faux :
        un processus actif dix minutes puis compromis génère des
        sous-séquences purement bénignes, qui hériteraient à tort de
        l'étiquette « attaque ». Elles gonflent les faux négatifs et
        dégradent le rappel sans qu'aucune attaque n'ait été manquée.

        Chaque sous-séquence est donc étiquetée d'après SES PROPRES
        événements : elle est « attaque » si elle en contient au moins un
        qui l'est.
    """
    from service_analysis import build_detector
    from analysis_agent.sequence_builder import SequenceBuilder

    detecteur, voies = build_detector()
    print(f"  détecteur chargé : {voies}"
          f"  (COMISET → seule la voie 'windows' est sollicitée)")

    builder = SequenceBuilder()
    y_vrai, y_pred, scores = [], [], []
    ignorees = 0
    n_sous_sequences = 0

    for i, ((hote, guid), evts) in enumerate(sequences):
        if i % 500 == 0 and i:
            print(f"    {i}/{len(sequences)} séquences…", flush=True)
        events = convertir_en_events(evts)
        if not events:
            ignorees += 1
            continue

        # vérité terrain par événement, repérée par son horodatage :
        # c'est le seul identifiant conservé lors de la conversion
        verite_par_temps = {}
        for e in evts:
            cle = str(e.get("@timestamp", "")).strip()
            if cle:
                verite_par_temps[cle] = (verite_par_temps.get(cle, False)
                                         or bool(e.get("_attaque")))

        sous = builder.build(events)
        n_sous_sequences += len(sous)
        for seq in sous:
            # une sous-séquence est attaque si ELLE contient un événement
            # étiqueté attaque ; à défaut d'appariement, on retombe sur
            # l'étiquette du groupe
            marques = []
            for ev in seq.events:
                t = getattr(ev, "event_time", None)
                if t is None:
                    continue
                cle = t.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
                if cle in verite_par_temps:
                    marques.append(verite_par_temps[cle])
            attendu = (int(any(marques)) if marques else etiquettes[i])

            res = detecteur.predict(seq)   # SequenceVerdict
            score = float(getattr(res, "attack_score", 0.0) or 0.0)
            predit = (score >= seuil) if seuil is not None \
                else bool(getattr(res, "is_attack", False))
            y_vrai.append(attendu)
            y_pred.append(int(predit))
            scores.append(score)

    if n_sous_sequences > len(sequences):
        print(f"    {len(sequences)} groupe(s) → {n_sous_sequences} "
              f"sous-séquence(s) après découpage temporel")
    return y_vrai, y_pred, scores, ignorees


# =============================================================================
def metriques(y_vrai: list[int], y_pred: list[int]) -> dict:
    """
    TP / FP / FN / TN et les métriques dérivées.

    Le FPR est explicitement calculé : c'est la métrique la plus révélatrice
    ici, puisqu'on a observé qu'une activité bénigne dense peut être classée
    en attaque (biais du corpus : EventID 11 et 13 y sont majoritairement
    associés à des attaques).
    """
    tp = sum(1 for v, p in zip(y_vrai, y_pred) if v == 1 and p == 1)
    fp = sum(1 for v, p in zip(y_vrai, y_pred) if v == 0 and p == 1)
    fn = sum(1 for v, p in zip(y_vrai, y_pred) if v == 1 and p == 0)
    tn = sum(1 for v, p in zip(y_vrai, y_pred) if v == 0 and p == 0)

    precision = tp / (tp + fp) if tp + fp else 0.0
    rappel = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * rappel / (precision + rappel) if precision + rappel else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    acc = (tp + tn) / len(y_vrai) if y_vrai else 0.0

    return {"TP": tp, "FP": fp, "FN": fn, "TN": tn,
            "precision": round(precision, 4), "recall": round(rappel, 4),
            "f1": round(f1, 4), "fpr": round(fpr, 4), "accuracy": round(acc, 4),
            "n_sequences": len(y_vrai)}


def courbe_seuils(y_vrai: list[int], scores: list[float]) -> list[dict]:
    """
    Un seuil différent améliorerait-il le compromis ?

    Réponse importante : on a mesuré que les plages de scores du bénin et
    de l'attaque se CHEVAUCHENT (poste sain à 1.000, attaque réelle à
    0.114). Si c'est confirmé ici, aucun seuil ne sépare les populations —
    et relever le seuil ne ferait que manquer des attaques.
    """
    out = []
    for s in (0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9):
        pred = [1 if x >= s else 0 for x in scores]
        m = metriques(y_vrai, pred)
        out.append({"seuil": s, **{k: m[k] for k in
                                   ("precision", "recall", "f1", "fpr")}})
    return out


# =============================================================================
def main() -> None:
    p = argparse.ArgumentParser(description="E2 — détection de menace")
    p.add_argument("--csv", required=True, help="CSV COMISET (Lab ou Real)")
    p.add_argument("--max", type=int, default=200000,
                   help="nombre de lignes lues (0 = tout)")
    p.add_argument("--seuil", type=float,
                   help="forcer un seuil (défaut : celui du modèle)")
    p.add_argument("--json", default="E2_detection_menace.json")
    args = p.parse_args()

    if not os.path.exists(args.csv):
        print(f"  fichier introuvable : {args.csv}")
        sys.exit(1)

    print("=" * 70)
    print("  E2 — DÉTECTION DE MENACE (voie Windows)")
    print("=" * 70)
    print(f"  corpus : {args.csv}")

    # déclaration d'indépendance du jeu — déterminante pour l'interprétation
    vu_a_lentrainement = "travail" in os.path.basename(args.csv).lower()
    if vu_a_lentrainement:
        print("  ⚠️ Ce corpus a servi à l'ENTRAÎNEMENT du détecteur.")
        print("     Les chiffres mesurent l'INTÉGRATION, pas la généralisation.")
    else:
        print("  mesure d'INTÉGRATION (le détecteur connaît ce corpus)")

    print(f"\n  chargement…")
    sequences, etiquettes, stats = charger_sequences(
        args.csv, args.max if args.max else None)
    print(f"    lignes lues            : {stats.get('lus', 0):,}")
    print(f"    sans process_guid      : {stats.get('sans_guid', 0):,}")
    print(f"    séquences trop courtes : {stats.get('sequences_trop_courtes', 0):,}")
    print(f"    séquences retenues     : {stats.get('sequences_retenues', 0):,}")
    print(f"      dont attaque         : {stats.get('sequences_attaque', 0):,}")
    print(f"      dont bénignes        : {stats.get('sequences_benignes', 0):,}")

    if not sequences:
        print("\n  aucune séquence analysable.")
        sys.exit(1)
    if stats.get("sequences_attaque", 0) == 0:
        print("\n  ⚠️ aucune séquence d'attaque : impossible de mesurer un rappel.")

    print(f"\n  évaluation…")
    y_vrai, y_pred, scores, ignorees = evaluer(sequences, etiquettes, args.seuil)
    if ignorees:
        print(f"    {ignorees} séquence(s) non convertibles (ignorées)")

    m = metriques(y_vrai, y_pred)
    print(f"\n{'=' * 70}\n  RÉSULTATS — {m['n_sequences']} séquences\n{'=' * 70}")
    print(f"    TP {m['TP']:6d}    FP {m['FP']:6d}")
    print(f"    FN {m['FN']:6d}    TN {m['TN']:6d}")
    print()
    print(f"    Precision : {m['precision']:.4f}")
    print(f"    Recall    : {m['recall']:.4f}")
    print(f"    F1        : {m['f1']:.4f}")
    print(f"    FPR       : {m['fpr']:.4f}")
    print(f"    Accuracy  : {m['accuracy']:.4f}")

    print(f"\n  RÉFÉRENCE (validation croisée du modèle seul, 5 plis)")
    print(f"    Recall 0.9060 | Precision 0.9500")
    ecart_r = m["recall"] - 0.906
    ecart_p = m["precision"] - 0.950
    print(f"    écart pipeline : recall {ecart_r:+.4f} | precision {ecart_p:+.4f}")

    # séparabilité des populations
    s_att = [s for s, v in zip(scores, y_vrai) if v == 1]
    s_ben = [s for s, v in zip(scores, y_vrai) if v == 0]
    if s_att and s_ben:
        print(f"\n  SÉPARABILITÉ DES POPULATIONS")
        print(f"    scores attaque : min {min(s_att):.3f}  max {max(s_att):.3f}")
        print(f"    scores bénin   : min {min(s_ben):.3f}  max {max(s_ben):.3f}")
        if max(s_ben) >= min(s_att):
            print(f"    → les plages SE CHEVAUCHENT : aucun seuil ne sépare")
            print(f"      les deux populations. Relever le seuil ne réduirait")
            print(f"      les faux positifs qu'au prix d'attaques manquées.")
        else:
            print(f"    → populations séparables : un seuil entre "
                  f"{max(s_ben):.3f} et {min(s_att):.3f} les distingue.")

    courbe = courbe_seuils(y_vrai, scores)
    print(f"\n  COMPROMIS SELON LE SEUIL")
    print(f"    {'seuil':>6s} {'precision':>10s} {'recall':>8s} {'F1':>7s} {'FPR':>7s}")
    for c in courbe:
        print(f"    {c['seuil']:6.1f} {c['precision']:10.4f} {c['recall']:8.4f} "
              f"{c['f1']:7.4f} {c['fpr']:7.4f}")

    resultat = {
        "corpus": args.csv,
        "vu_a_lentrainement": vu_a_lentrainement,
        "statistiques_corpus": stats,
        "metriques": m,
        "reference_validation_croisee": {"recall": 0.906, "precision": 0.950},
        "separabilite": {"score_max_benin": max(s_ben) if s_ben else None,
                         "score_min_attaque": min(s_att) if s_att else None},
        "courbe_seuils": courbe,
    }
    with open(args.json, "w", encoding="utf-8") as f:
        json.dump(resultat, f, ensure_ascii=False, indent=2)
    print(f"\n  RÉSERVES À DÉCLARER AVEC CES CHIFFRES")
    print(f"    · corpus à 5 % de bénin : le FPR SOUS-ESTIME celui d'un")
    print(f"      déploiement réel, où le trafic bénin domine ;")
    print(f"    · le détecteur a été entraîné sur ce corpus : ces chiffres")
    print(f"      mesurent l'INTÉGRATION, pas la généralisation ;")
    print(f"    · référence de généralisation : validation croisée 5 plis")
    print(f"      (recall 0.906, precision 0.950) ;")
    print(f"    · mesure sur environnement inédit à venir : COMISET Real.")
    print(f"\n  résultats exportés : {args.json}")


if __name__ == "__main__":
    main()
