"""
=============================================================================
RÉENTRAÎNEMENT DU DÉTECTEUR WINDOWS — ratio réaliste, corpus Real
=============================================================================
⚠️ CE QUE CE SCRIPT CORRIGE, ET CE QU'IL NE CORRIGE PAS

    Le détecteur actuel obtient un rappel de 0,950 mais un FPR de 0,635
    (voir E2). La vérification du code n'a révélé AUCUN bug — contrairement
    à l'autoencodeur, où le problème venait de `evaluer()` et d'un seuil
    hors domaine. Ici, correspondance exacte des 18 features, mode aligné
    actif, seuil correctement appliqué, `class_weight="balanced"` en place.

    Deux causes réelles subsistent, toutes deux liées aux DONNÉES :

      1. RATIO IRRÉALISTE — `comiset_travail.csv` contient 42 % d'attaques
         (1,71 M contre 2,39 M bénins) alors que la réalité est à ~3 %. Le
         modèle a appris un monde où l'attaque est courante, donc « dans le
         doute, c'est une attaque ».

      2. SEUIL BAS ASSUMÉ — 0,3, avec `orientation: recall-oriented` inscrit
         dans la configuration. Un seuil bas produit MÉCANIQUEMENT des faux
         positifs : c'était le but recherché.

    Ce script traite la cause 1. La cause 2 est un choix de conception, pas
    un défaut — on le laisse tel quel, mais on mesure le compromis obtenu à
    différents seuils pour éclairer la décision.

⚠️ CE QU'UN ÉCHEC SIGNIFIERAIT
    E2 montre que les distributions de scores se recouvrent ENTIÈREMENT sur
    [0, 1]. Si ce recouvrement persiste après réentraînement, cela ne
    signifiera pas « le réentraînement a échoué » mais « les 18 features
    structurelles ne suffisent pas à séparer les populations » — un résultat
    différent, qui orienterait vers l'enrichissement des features plutôt que
    vers les données.

⚠️ DÉCOUPAGE PAR HÔTE, PAS PAR SÉQUENCE
    Un découpage aléatoire mettrait des séquences du même hôte des deux
    côtés. Le modèle reconnaîtrait des habitudes déjà vues — une fuite, pas
    de la généralisation. On reprend le découpage validé en E0 : 8 hôtes
    d'entraînement, 5 de test, sans recoupement.

USAGE
    python3 services/reentrainer_detecteur_windows.py \
        --benin real_entrainement.csv \
        --attaques real_entrainement_attaques.csv \
        --ratio-attaque 0.05
=============================================================================
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import random
import sys
from collections import Counter, defaultdict

_ICI = os.path.dirname(os.path.abspath(__file__))
_RACINE = os.path.dirname(_ICI)
for chemin in (_ICI, _RACINE,
               os.path.join(_RACINE, "agents", "1_collect_agent"),
               os.path.join(_RACINE, "agents", "2_analysis_agent")):
    if chemin not in sys.path:
        sys.path.insert(0, chemin)


def controler_comparabilite(groupes: dict, seuil_divergence: float = 0.30) -> dict:
    """
    ⚠️ GARDE-FOU — LES DEUX CLASSES DOIVENT ÊTRE COMPARABLES.
        Si les logs bénins et les logs d'attaque proviennent d'extractions
        DIFFÉRENTES, leurs profils d'EventID peuvent diverger complètement.
        Le modèle apprend alors à distinguer les EXTRACTIONS, pas les
        attaques — et affiche des scores parfaits sans aucune valeur.

        Constaté : bénin à 98,9 % d'EventID 10 (ProcessAccess) contre
        attaques à 83,8 % d'EventID 7 (ImageLoad), parce que le bénin avait
        été sous-échantillonné à 2 % (préservant la proportion du corpus,
        donc ProcessAccess) tandis que les attaques étaient conservées
        intégralement. Résultat : FPR de 0,001 — trivial à obtenir en
        séparant deux types d'événements, sans rapport avec la détection.

        On mesure donc la divergence des distributions d'EventID entre
        classes AVANT d'entraîner, et on refuse si elle est trop forte.
    """
    # ⚠️ AGRÉGER PAR PROCESSUS, PAS PAR LOG.
    #    L'entraînement étiquette une SÉQUENCE : elle est « attaque » si elle
    #    contient au moins un log étiqueté. La comparabilité doit se mesurer
    #    au même grain.
    #
    #    Mesurer par log compare les logs PORTANT une étiquette (majoritairement
    #    des EventID 7, où T1055 est annoté) au reste — et annonce 89,9 % de
    #    divergence sur un corpus que l'extraction, mesurant par processus,
    #    donne à 1,1 %. Les deux chiffres sont exacts, mais un seul répond à
    #    la question posée : les SÉQUENCES des deux classes sont-elles
    #    comparables ?
    dist = {0: Counter(), 1: Counter()}
    for lignes in groupes.values():
        classe = int(any(l.get("_attaque") for l in lignes))
        for l in lignes:
            dist[classe][str(l.get("event_id", "?"))] += 1

    tot = {c: sum(d.values()) or 1 for c, d in dist.items()}
    eids = set(dist[0]) | set(dist[1])
    # distance de variation totale entre les deux distributions
    divergence = 0.5 * sum(
        abs(dist[1][e] / tot[1] - dist[0][e] / tot[0]) for e in eids)

    print(f"\n  CONTRÔLE DE COMPARABILITÉ DES CLASSES")
    print(f"      {'EventID':>9s} {'bénin':>10s} {'attaque':>10s}")
    for e, _ in sorted(eids and Counter(
            {x: dist[1][x] + dist[0][x] for x in eids}).most_common(6)):
        print(f"      {e:>9s} {dist[0][e]/tot[0]:>9.1%} "
              f"{dist[1][e]/tot[1]:>10.1%}")
    print(f"\n      divergence des profils : {divergence:.1%}")

    acceptable = divergence <= seuil_divergence
    if not acceptable:
        print(f"      ⚠️ DIVERGENCE TROP FORTE (> {seuil_divergence:.0%})")
        print(f"         Les deux classes ne proviennent pas du même type")
        print(f"         d'extraction. Un modèle entraîné ainsi apprendrait à")
        print(f"         distinguer les EXTRACTIONS, pas les attaques.")
        print(f"         → extraire bénins ET attaques du MÊME flux, avec le")
        print(f"           MÊME traitement (voir extraire_classes_comparables.py)")
    else:
        print(f"      → profils comparables, l'entraînement peut porter sur")
        print(f"        la différence attaque/bénin et non sur l'extraction.")
    return {"divergence": round(divergence, 4), "acceptable": acceptable,
            "profil_benin": dict(dist[0].most_common(10)),
            "profil_attaque": dict(dist[1].most_common(10))}


def charger_groupes(chemin: str, maximum: int | None = None) -> dict:
    """
    Regroupe les logs par (hôte, process_guid) — le grain de séquençage du
    détecteur. Conserve l'étiquette de chaque événement.
    """
    groupes = defaultdict(list)
    n = 0
    with open(chemin, newline="", encoding="utf-8", errors="ignore") as f:
        for ligne in csv.DictReader(f):
            if maximum and n >= maximum:
                break
            guid = (ligne.get("process_guid") or "").strip()
            hote = (ligne.get("host_name") or "").strip()
            if not guid or not hote:
                continue
            ligne["_attaque"] = bool((ligne.get("rule_technique_id") or "").strip())
            groupes[(hote, guid)].append(ligne)
            n += 1
    return groupes


def construire_sequences(groupes: dict, min_events: int = 3):
    """
    Convertit les groupes en objets Sequence, avec leur étiquette.

    ⚠️ Une séquence est ATTAQUE si elle contient au moins un événement
    étiqueté attaque — même convention que E2, pour que les mesures restent
    comparables.
    """
    from collect_agent.sysmon_mapper import map_sysmon_event
    from analysis_agent.sequence_builder import SequenceBuilder
    from service_collect import _serialize_log
    from service_analysis import logs_to_events

    builder = SequenceBuilder()
    sequences, labels, hotes = [], [], []
    for (hote, guid), lignes in groupes.items():
        if len(lignes) < min_events:
            continue
        bruts = []
        for l in lignes:
            h = (l.get("@timestamp") or "").strip()
            if not h:
                continue
            h = h.replace("T", " ").replace("Z", "")
            if "." not in h:
                h += ".000"
            eid = (l.get("event_id") or "").strip()
            if not eid:
                continue
            bruts.append({
                "EventID": eid, "UtcTime": h[:23], "Computer": hote,
                "ProcessGuid": guid,
                "Image": (l.get("process_path") or l.get("process_name") or "").strip(),
            })
        if len(bruts) < min_events:
            continue

        logs = []
        for b in bruts:
            r = map_sysmon_event(b, replay_mode=True)
            lg = getattr(r, "log", None)
            if lg is not None:
                logs.append(_serialize_log(lg))
        if not logs:
            continue
        events, _ = logs_to_events(logs)
        if not events:
            continue

        etiquette = int(any(l["_attaque"] for l in lignes))
        for seq in builder.build(events):
            sequences.append(seq)
            labels.append(etiquette)
            hotes.append(hote)
    return sequences, labels, hotes


def equilibrer(sequences, labels, hotes, ratio_attaque: float, seed: int = 42):
    """
    Ramène la proportion d'attaques au ratio visé, en sous-échantillonnant
    la classe majoritaire — SANS jamais dupliquer d'exemples.

    ⚠️ On ne sur-échantillonne pas les attaques : dupliquer des séquences
    identiques ferait croire au modèle qu'elles sont plus fréquentes qu'elles
    ne le sont, et gonflerait artificiellement la confiance sur ces motifs
    précis. On retire du bénin, on n'invente rien.
    """
    rng = random.Random(seed)
    idx_att = [i for i, l in enumerate(labels) if l == 1]
    idx_ben = [i for i, l in enumerate(labels) if l == 0]

    # combien de bénins pour que les attaques représentent `ratio_attaque` ?
    n_ben_cible = int(len(idx_att) * (1 - ratio_attaque) / max(ratio_attaque, 1e-6))
    if n_ben_cible < len(idx_ben):
        idx_ben = rng.sample(idx_ben, n_ben_cible)
    else:
        # pas assez de bénin disponible : on réduit les attaques à la place
        n_att_cible = int(len(idx_ben) * ratio_attaque / max(1 - ratio_attaque, 1e-6))
        if n_att_cible < len(idx_att):
            idx_att = rng.sample(idx_att, n_att_cible)

    garde = sorted(idx_att + idx_ben)
    return ([sequences[i] for i in garde], [labels[i] for i in garde],
            [hotes[i] for i in garde])


def evaluer(det, sequences, labels, seuils=(0.3, 0.5, 0.7, 0.9)) -> dict:
    """Mesure aux différents seuils, pour éclairer le compromis."""
    scores = []
    for seq in sequences:
        res = det.predict(seq)
        scores.append(float(getattr(res, "attack_score", 0.0) or 0.0))

    resultats = {}
    for s in seuils:
        tp = sum(1 for sc, l in zip(scores, labels) if sc >= s and l == 1)
        fp = sum(1 for sc, l in zip(scores, labels) if sc >= s and l == 0)
        fn = sum(1 for sc, l in zip(scores, labels) if sc < s and l == 1)
        tn = sum(1 for sc, l in zip(scores, labels) if sc < s and l == 0)
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        fpr = fp / (fp + tn) if fp + tn else 0.0
        resultats[s] = {"TP": tp, "FP": fp, "FN": fn, "TN": tn,
                        "precision": round(prec, 4), "recall": round(rec, 4),
                        "f1": round(f1, 4), "fpr": round(fpr, 4)}

    # séparabilité : le point qui décidera si les features suffisent
    s_att = [sc for sc, l in zip(scores, labels) if l == 1]
    s_ben = [sc for sc, l in zip(scores, labels) if l == 0]
    sep = {}
    if s_att and s_ben:
        sep = {"attaque_min": round(min(s_att), 4), "attaque_max": round(max(s_att), 4),
               "benin_min": round(min(s_ben), 4), "benin_max": round(max(s_ben), 4),
               "recouvrement_total": min(s_ben) <= min(s_att) and max(s_ben) >= max(s_att)}
    return {"par_seuil": resultats, "separabilite": sep}


# =============================================================================
def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--benin", required=True, help="real_entrainement.csv")
    p.add_argument("--attaques", required=True,
                   help="real_entrainement_attaques.csv")
    p.add_argument("--max-benin", type=int, default=800_000)
    p.add_argument("--max-attaques", type=int, default=400_000)
    p.add_argument("--ratio-attaque", type=float, default=0.05,
                   help="proportion d'attaques visée (réalité ~0.03)")
    p.add_argument("--sortie-modele", default="windows_detector_v2.pkl")
    p.add_argument("--sortie-config", default="windows_detector_v2_config.pkl")
    p.add_argument("--forcer", action="store_true",
                   help="entraîner malgré une divergence de profils entre "
                        "classes — le résultat serait ininterprétable")
    p.add_argument("--json", default="reentrainement_detecteur.json")
    args = p.parse_args()

    print("=" * 70)
    print("  RÉENTRAÎNEMENT DU DÉTECTEUR WINDOWS — ratio réaliste")
    print("=" * 70)

    print(f"\n  chargement…")
    groupes = charger_groupes(args.benin, args.max_benin)
    print(f"    bénin    : {len(groupes):,} groupe(s) (host, process_guid)")
    g_att = charger_groupes(args.attaques, args.max_attaques)
    print(f"    attaques : {len(g_att):,} groupe(s)")
    for k, v in g_att.items():
        groupes[k].extend(v)

    ctrl = controler_comparabilite(groupes)
    if not ctrl["acceptable"] and not args.forcer:
        print(f"\n  Entraînement ABANDONNÉ. Utiliser --forcer pour passer")
        print(f"  outre (le résultat serait alors ininterprétable).")
        sys.exit(1)

    print(f"\n  construction des séquences…")
    sequences, labels, hotes = construire_sequences(groupes)
    n_att = sum(labels)
    print(f"    {len(sequences):,} séquence(s) | {n_att:,} attaque(s) "
          f"({n_att/max(1,len(labels)):.1%})")

    if n_att < 100:
        print(f"\n  ⚠️ Trop peu d'attaques ({n_att}) pour entraîner. "
              f"Augmenter --max-attaques.")
        sys.exit(1)

    print(f"\n  rééquilibrage vers {args.ratio_attaque:.0%} d'attaques…")
    sequences, labels, hotes = equilibrer(sequences, labels, hotes,
                                          args.ratio_attaque)
    n_att2 = sum(labels)
    print(f"    {len(sequences):,} séquence(s) | {n_att2:,} attaque(s) "
          f"({n_att2/max(1,len(labels)):.1%})")

    # --- découpage PAR HÔTE ---------------------------------------------
    hotes_uniques = sorted(set(hotes))
    rng = random.Random(42)
    rng.shuffle(hotes_uniques)
    n_test = max(1, len(hotes_uniques) // 3)
    hotes_test = set(hotes_uniques[:n_test])
    print(f"\n  découpage PAR HÔTE — {len(hotes_uniques)} hôte(s)")
    print(f"    test  : {sorted(hotes_test)}")

    i_train = [i for i, h in enumerate(hotes) if h not in hotes_test]
    i_test = [i for i, h in enumerate(hotes) if h in hotes_test]
    seq_tr = [sequences[i] for i in i_train]
    lab_tr = [labels[i] for i in i_train]
    seq_te = [sequences[i] for i in i_test]
    lab_te = [labels[i] for i in i_test]
    print(f"    entraînement : {len(seq_tr):,} ({sum(lab_tr):,} attaques)")
    print(f"    test         : {len(seq_te):,} ({sum(lab_te):,} attaques)")

    if not seq_te or sum(lab_te) == 0:
        print(f"\n  ⚠️ Jeu de test vide ou sans attaque — découpage inexploitable.")
        sys.exit(1)

    print(f"\n  entraînement…")
    from analysis_agent.unified_detector import UnifiedSequenceDetector
    det = UnifiedSequenceDetector(aligned_windows_features=True,
                                  recall_threshold=0.3)
    det.fit_endpoint(seq_tr, lab_tr)
    print(f"    fait")

    print(f"\n  ÉVALUATION sur les hôtes de test (jamais vus)")
    res = evaluer(det, seq_te, lab_te)
    print(f"      {'seuil':>6s} {'précision':>10s} {'rappel':>8s} "
          f"{'F1':>7s} {'FPR':>7s}")
    for s, m in res["par_seuil"].items():
        print(f"      {s:>6.1f} {m['precision']:>10.3f} {m['recall']:>8.3f} "
              f"{m['f1']:>7.3f} {m['fpr']:>7.3f}")

    sep = res["separabilite"]
    if sep:
        print(f"\n  SÉPARABILITÉ")
        print(f"      scores attaque : {sep['attaque_min']:.3f} – "
              f"{sep['attaque_max']:.3f}")
        print(f"      scores bénin   : {sep['benin_min']:.3f} – "
              f"{sep['benin_max']:.3f}")
        if sep["recouvrement_total"]:
            print(f"\n      ⚠️ RECOUVREMENT TOTAL — comme avant réentraînement.")
            print(f"         Les 18 features structurelles ne suffisent pas à")
            print(f"         séparer les populations sur ce corpus. Le")
            print(f"         problème n'est PAS le ratio d'entraînement :")
            print(f"         il faut enrichir les features, pas les données.")
        else:
            print(f"\n      → Les plages ne se recouvrent plus entièrement :")
            print(f"        le rééquilibrage a amélioré la séparabilité.")

    # --- comparaison à la référence E2 -----------------------------------
    ref = {"recall": 0.950, "fpr": 0.635, "precision": 0.773}
    m03 = res["par_seuil"].get(0.3, {})
    print(f"\n  COMPARAISON À E2 (détecteur actuel, seuil 0,3)")
    print(f"      {'':12s} {'E2':>8s} {'v2':>8s} {'écart':>8s}")
    for cle in ("recall", "precision", "fpr"):
        a, b = ref[cle], m03.get(cle, 0.0)
        print(f"      {cle:12s} {a:>8.3f} {b:>8.3f} {b-a:>+8.3f}")

    import joblib
    # ⚠️ SAUVEGARDER LE SCALER AVEC LE MODÈLE.
    #    `SubDetector.fit()` fait `self.scaler.fit_transform(X)` puis entraîne
    #    sur des features NORMALISÉES. Ne sauvegarder que `model` perd le
    #    scaler ajusté : au chargement, `model_loader` installe un
    #    `_IdentityScaler` (correct pour le modèle d'origine, entraîné SANS
    #    normalisation) et le modèle reçoit alors des features BRUTES.
    #
    #    Symptôme mesuré : scores écrasés entre 0,11 et 0,35, jamais au-delà,
    #    rappel effondré à 0,018 via E2 — alors que le même modèle donnait
    #    0,882 dans ce script, où le scaler était encore en mémoire.
    #    C'est exactement le défaut déjà rencontré sur l'autoencodeur.
    joblib.dump({"model": det._endpoint.model,
                 "scaler": det._endpoint.scaler},
                args.sortie_modele)
    from analysis_agent.windows_features_aligned import WINDOWS_FEATURE_NAMES
    joblib.dump({"threshold": 0.3, "dataset": "COMISET Real (ratio réaliste)",
                 "sequencing": "par process_guid, plafond 200 événements",
                 "n_features": len(WINDOWS_FEATURE_NAMES),
                 "feature_names": list(WINDOWS_FEATURE_NAMES),
                 "orientation": "rappel (recall-oriented)",
                 "ratio_attaque_entrainement": args.ratio_attaque,
                 "hotes_test": sorted(hotes_test)},
                args.sortie_config)
    print(f"\n  modèle : {args.sortie_modele}")
    print(f"  config : {args.sortie_config}")

    with open(args.json, "w", encoding="utf-8") as f:
        json.dump({"comparabilite": ctrl,
                   "evaluation": res, "reference_E2": ref,
                   "n_train": len(seq_tr), "n_test": len(seq_te),
                   "hotes_test": sorted(hotes_test)},
                  f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
