"""
=============================================================================
E3 — ROBUSTESSE AUX FALSIFICATIONS DE JOURNAUX
=============================================================================
Le système détecte-t-il qu'on a manipulé les preuves — et cette détection
change-t-elle la décision ?

⚠️ CE QUE CETTE EXPÉRIENCE MESURE, QUE E2 NE MESURE PAS
    E2 évalue la détection d'ATTAQUE. E3 évalue la détection de FALSIFICATION :
    un attaquant qui efface ses traces, décale des horodatages ou insère de
    faux événements. Ce sont deux problèmes distincts — un journal peut être
    falsifié sans qu'aucune attaque n'y soit visible, c'est même le but.

    C'est une contribution propre à ce travail : la plupart des systèmes de
    détection supposent leurs journaux fiables. Ici, l'intégrité est évaluée
    explicitement et devient un signal de décision.

TROIS MESURES

  [A] DÉTECTION      Sur un corpus dont on connaît exactement les
                     falsifications injectées, combien sont repérées ?
                     Precision, Recall, F1 par TYPE de falsification.

  [B] RÈGLES         Quelle règle attrape quoi ? Une règle qui ne se
                     déclenche jamais est du code mort ; une règle qui se
                     déclenche sur tout est du bruit.

  [C] PROPAGATION    La falsification atteint-elle la décision ?
                     ⚠️ C'est le point critique. La règle R2 du Decision
                     Agent — « menace + falsification = confirmation » — ne
                     peut se déclencher que si le signal traverse la chaîne.
                     Cette relation manquait jusqu'à hier : le Collect
                     détectait mais ne transmettait à personne.

VÉRITÉ TERRAIN
    Fournie par `FalsificationGenerator`, qui applique des falsifications
    contrôlées à des logs authentiques et conserve la trace exacte de ce
    qu'il a modifié (index, type, détail).

⚠️ LIMITE À DÉCLARER
    Les falsifications sont INJECTÉES, non observées. Un attaquant réel
    pourrait opérer autrement — effacer proprement via l'API Windows plutôt
    que de trouer les record-ID, par exemple. Ces chiffres mesurent la
    détection des falsifications MODÉLISÉES, pas de toutes les falsifications
    possibles.

USAGE
    python3 E3_robustesse_integrite.py --csv comiset_travail.csv
    python3 E3_robustesse_integrite.py --csv comiset_travail.csv --taux 0.10
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
for chemin in (_ICI, _RACINE,
               os.path.join(_RACINE, "agents", "1_collect_agent"),
               os.path.join(_RACINE, "agents", "2_analysis_agent"),
               os.path.join(_RACINE, "agents", "4_decision_agent"),
               os.path.join(_RACINE, "cloud_adapter")):
    if chemin not in sys.path:
        sys.path.insert(0, chemin)


# =============================================================================
def charger_logs_authentiques(chemin: str, maximum: int) -> list:
    """
    Charge des logs COMISET RÉELS et les mappe en CanonicalLog.

    ⚠️ On part de logs authentiques, jamais de logs synthétiques : les
    falsifications doivent s'appliquer à des données au profil réel, sinon
    la détection serait facilitée artificiellement (un log fabriqué est déjà
    anormal avant toute falsification).

    ⚠️ `replay_mode` est ACTIVÉ. COMISET date de 2022 : sans lui, la règle R3
    (dérive d'horloge) se déclencherait sur CHAQUE événement, puisqu'ils sont
    ingérés des années après leur émission. On mesurerait alors le décalage
    du rejeu, pas la falsification.
    """
    from collect_agent.sysmon_mapper import map_sysmon_event

    logs = []
    with open(chemin, newline="", encoding="utf-8", errors="ignore") as f:
        for i, ligne in enumerate(csv.DictReader(f)):
            if len(logs) >= maximum:
                break
            horodatage = (ligne.get("@timestamp") or "").strip()
            if not horodatage:
                continue
            horodatage = horodatage.replace("T", " ").replace("Z", "")
            if "." not in horodatage:
                horodatage += ".000"
            brut = {
                "EventID": (ligne.get("event_id") or "").strip(),
                "UtcTime": horodatage[:23],
                "Computer": (ligne.get("host_name") or "inconnu").strip(),
                "ProcessGuid": (ligne.get("process_guid") or "").strip(),
                "Image": (ligne.get("process_path")
                          or ligne.get("process_name") or "").strip(),
            }
            # ⚠️ RecordNumber ACTIVE `RecordGapDetector`, le détecteur
            #    DÉTERMINISTE de suppression de logs. Sans lui, `log.raw_ref`
            #    reste None et `check()` retourne None sans jamais analyser —
            #    seul le détecteur STATISTIQUE (SilenceGapDetector) restait
            #    actif, avec une précision de 0.031 sur du trafic Windows en
            #    rafales. La suppression était alors mesurée à 0.000 de
            #    rappel : un mécanisme débranché, pas une limite réelle.
            #    Absent de comiset_travail.csv d'origine, présent dans
            #    comiset_travail_v2.csv (voir reextraire_lab_avec_record.py).
            record = (ligne.get("record_number") or "").strip()
            if record:
                brut["RecordNumber"] = record
            resultat = map_sysmon_event(brut, replay_mode=True)
            log = getattr(resultat, "log", None)
            if log is not None:
                logs.append(log)
    return logs


# =============================================================================
def mesurer_detection(logs: list, taux: float, graine: int = 42,
                      modele_ae: str | None = None,
                      config_ae: str | None = None,
                      zones: int = 0) -> dict:
    """
    ⚠️ PARAMÈTRE `zones` — INDISPENSABLE POUR UNE MESURE HONNÊTE
        Avec des falsifications DISPERSÉES aléatoirement (zones=0), un taux
        de 5 % sur 20 000 logs touche presque TOUTES les fenêtres de 100 :
        mesuré, 195 fenêtres falsifiées sur 200, soit TN = 0.

        Une précision de 0.975 dans ces conditions ne prouve RIEN — signaler
        systématiquement tout donnerait déjà 0.975, puisque 97,5 % des
        fenêtres sont effectivement falsifiées. Et un détecteur qui signale
        aussi les 5 fenêtres saines restantes reste indistinguable d'un bon
        détecteur.

        Avec `zones=N`, les falsifications sont regroupées dans N régions
        contiguës du corpus. Le reste du journal est INTACT, ce qui crée de
        vraies fenêtres négatives — les seules qui permettent de mesurer un
        taux de faux positifs réel.
    """
    """
    [A] et [B] — sur un corpus dont on connaît les falsifications injectées,
    lesquelles sont repérées, et par quelle règle ?
    """
    from collect_agent.falsification_generator import FalsificationGenerator
    from collect_agent.collect_agent import CollectAgent, CollectOutputs

    print(f"\n  [A] DÉTECTION — falsification de {taux:.0%} du corpus")
    generateur = FalsificationGenerator(seed=graine)
    if zones <= 0:
        jeu = generateur.generate(logs, ratio=taux)
    else:
        # ⚠️ FALSIFICATION PAR ZONES CONTIGUËS
        #    Le générateur ne sait falsifier qu'un corpus entier, en
        #    dispersant. On découpe donc nous-mêmes : `zones` tranches sont
        #    falsifiées (à un ratio relevé pour conserver le même volume
        #    total de falsifications), le RESTE du corpus reste INTACT.
        #    Ce sont ces régions intactes qui fournissent les vraies
        #    fenêtres négatives, absentes du mode dispersé.
        from collect_agent.falsification_generator import FalsifiedDataset

        n = len(logs)
        taille_zone = max(200, n // (zones * 3))   # zones ≈ 1/3 du corpus
        pas = n // zones
        ratio_zone = min(0.30, taux * 3)           # même volume, concentré

        logs_finaux, gt_total, ids_total = [], [], set()
        curseur = 0
        for k in range(zones):
            debut = k * pas
            fin = min(debut + taille_zone, n)
            # région intacte avant la zone
            logs_finaux.extend(logs[curseur:debut])
            # zone falsifiée
            sous = logs[debut:fin]
            if sous:
                sous_jeu = generateur.generate(list(sous), ratio=ratio_zone)
                logs_finaux.extend(sous_jeu.logs)
                gt_total.extend(sous_jeu.ground_truth)
                ids_total |= set(sous_jeu.tampered_event_ids)
            curseur = fin
        logs_finaux.extend(logs[curseur:])          # queue intacte

        jeu = FalsifiedDataset(logs=logs_finaux, ground_truth=gt_total,
                               tampered_event_ids=ids_total,
                               original_count=n)
        print(f"      {zones} zone(s) falsifiée(s) de ~{taille_zone} logs "
              f"(ratio {ratio_zone:.0%}), reste du corpus INTACT")

    # ⚠️ Identifier les logs falsifiés par leur ID, jamais par leur index :
    #    la suppression et l'injection DÉCALENT les positions, un index du
    #    corpus original ne désigne plus le même log après falsification.
    falsifies_ids = set(jeu.tampered_event_ids)
    print(f"      {len(jeu.logs):,} logs | {len(falsifies_ids):,} falsifié(s)")
    repartition = Counter(e.falsification_type.value for e in jeu.ground_truth)
    for t, n in repartition.most_common():
        print(f"        {t:16s} {n:,}")

    collect = CollectAgent(replay_mode=True)
    collect.outputs = CollectOutputs()
    from cloud_adapter.cloud_to_collect import process_canonical_logs
    sorties = process_canonical_logs(collect, jeu.logs)

    # ⚠️ Le détecteur déterministe se désactive si la séquence de
    #    RecordNumber n'est pas ordonnée (voir RecordGapDetector). Une
    #    absence de `record_gap` peut donc signifier « aucun trou » OU
    #    « impossible à juger » — deux choses très différentes, qu'il
    #    serait fautif de confondre dans un rapport.
    try:
        diag = collect.gap_engine.diagnostic_ordre()
        desactives = {k: v for k, v in diag.items() if v.get("desactive")}
        if desactives:
            print(f"\n      ⚠️ DÉTECTEUR DÉTERMINISTE DÉSACTIVÉ "
                  f"({len(desactives)} source(s))")
            for k, v in list(desactives.items())[:5]:
                print(f"         {k} : {v['taux']:.1%} de reculs sur "
                      f"{v['vus']:,} logs")
            print(f"         → la séquence de RecordNumber n'est pas "
                  f"ordonnée sur cette")
            print(f"           entrée. L'absence de `record_gap` ci-dessous "
                  f"ne signifie")
            print(f"           donc PAS « aucun trou », mais « non "
                  f"mesurable ici ».")
    except AttributeError:
        pass

    # identifiants des logs signalés + règles déclenchées
    signales, regles_par_id = set(), defaultdict(list)
    for enrichi in sorties.enriched:
        annotations = getattr(enrichi, "annotations", None) or []
        if not annotations:
            continue
        eid = str(getattr(enrichi.log, "event_id", ""))
        signales.add(eid)
        for a in annotations:
            detail = str(getattr(a, "detail", ""))
            kind = str(getattr(a, "kind", ""))
            if "]" in detail:
                # règle forensique : « [R1_timestomping] … »
                regle = detail.split("]")[0].lstrip("[")
            elif kind == "tampering_ml":
                # l'autoencodeur ne porte pas de préfixe de règle
                regle = "AE_autoencodeur"
            else:
                regle = kind or "autre"
            regles_par_id[eid].append(regle)

    tp = len(falsifies_ids & signales)
    fp = len(signales - falsifies_ids)
    fn = len(falsifies_ids - signales)
    tn = len(jeu.logs) - tp - fp - fn
    precision = tp / (tp + fp) if tp + fp else 0.0
    rappel = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * rappel / (precision + rappel) if precision + rappel else 0.0

    print(f"\n      TP {tp:,}  FP {fp:,}  FN {fn:,}  TN {tn:,}")
    print(f"      Precision {precision:.3f} | Recall {rappel:.3f} | F1 {f1:.3f}")

    # ⚠️ LIRE CETTE PRÉCISION AVEC PRÉCAUTION
    #    Une falsification ne se limite pas au log qu'elle touche : déplacer
    #    un log rend anormaux TOUS ceux qui le suivent, supprimer un bloc
    #    décale toute la suite. R5 (désordre chronologique) signale donc
    #    légitimement des logs que la vérité terrain ne marque pas — ils ne
    #    sont pas falsifiés eux-mêmes, mais ils PORTENT LA TRACE de la
    #    falsification voisine.
    #
    #    Ces signalements sont comptés « faux positifs » alors qu'ils sont
    #    l'effet attendu d'une manipulation réelle. La précision au grain du
    #    LOG sous-estime donc la qualité de détection. La mesure pertinente
    #    est au grain de la FENÊTRE : le système signale-t-il les zones du
    #    journal qui ont été manipulées ?
    if fp > tp:
        print(f"\n      ⚠️ Les FP dépassent les TP. Vérifier ci-dessous quelle")
        print(f"         règle les produit : une falsification CONTAMINE ses")
        print(f"         voisins (un log déplacé rend anormaux tous les")
        print(f"         suivants). Ces signalements ne sont pas des erreurs,")
        print(f"         mais l'effet de propagation de la manipulation.")

    # --- rappel par type de falsification, AU GRAIN DU LOG ---
    print(f"\n      détection par TYPE de falsification (grain du LOG)")
    # ⚠️ Association FIABLE par event_id — voir la note détaillée plus bas
    #    dans mesurer_detection() pour l'historique du bug corrigé (tri
    #    arbitraire d'IDs supposé aligné sur l'ordre de génération, ce qui
    #    était faux et associait silencieusement de mauvais types à de
    #    mauvais logs, sauf coïncidence).
    #
    # ⚠️ LA SUPPRESSION EST EXCLUE DE CE TABLEAU, VOLONTAIREMENT.
    #    Un log supprimé n'existe plus dans le corpus : son event_id
    #    n'apparaît dans aucune annotation, donc ce croisement afficherait
    #    invariablement 0/N — un « zéro » qui ne mesure RIEN et se lit à tort
    #    comme « indétectable ». Elle est mesurée PAR POSITION du trou, plus
    #    bas, où elle atteint un rappel de 1.000.
    par_type = defaultdict(lambda: [0, 0])   # [détectés, total]
    for entree in jeu.ground_truth:
        if not entree.event_id:
            continue
        cle = entree.falsification_type.value
        if cle == "suppression":
            continue          # non mesurable à ce grain — voir note ci-dessus
        par_type[cle][1] += 1
        if entree.event_id in signales:
            par_type[cle][0] += 1
    detail_types = {}
    for t, (d, n) in sorted(par_type.items()):
        r = d / n if n else 0.0
        detail_types[t] = {"detectes": d, "total": n, "rappel": round(r, 4)}
        print(f"        {t:16s} {d:>5,}/{n:<5,}  rappel {r:.3f}")
    print(f"        {'suppression':16s} {'—':>11s}  mesurée par position "
          f"(voir plus bas)")

    # --- [B] quelle règle attrape quoi ---
    print(f"\n  [B] RÈGLES — laquelle se déclenche, et sur quoi ?")
    usage = Counter()
    justesse = defaultdict(lambda: [0, 0])   # [sur falsifié, total]
    for eid, regles in regles_par_id.items():
        for r in set(regles):
            usage[r] += 1
            justesse[r][1] += 1
            if eid in falsifies_ids:
                justesse[r][0] += 1
    if usage:
        print(f"        {'règle':22s} {'décl.':>7s} {'justes':>7s} {'préc.':>7s}")
        detail_regles = {}
        for r, n in usage.most_common():
            j, t = justesse[r]
            p = j / t if t else 0.0
            detail_regles[r] = {"declenchements": n, "sur_falsifie": j,
                                "precision": round(p, 4)}
            print(f"        {r:22s} {n:>7,} {j:>7,} {p:>7.3f}")
    else:
        detail_regles = {}
        print("        aucune règle déclenchée — vérifier le rejeu")

    inactives = {"R1_timestomping", "R2_future_timestamp", "R3_clock_skew",
                 "R4_self_parent", "R5_out_of_order", "R6_time_change",
                 "R7_log_cleared", "R8_eventlog_stopped",
                 "R9_record_gap"} - set(usage)
    if inactives:
        print(f"\n        règles JAMAIS déclenchées : {', '.join(sorted(inactives))}")
        print(f"        → soit le corpus ne contient pas ces cas, soit ces")
        print(f"          règles sont inopérantes. À distinguer avant de")
        print(f"          conclure quoi que ce soit sur leur utilité.")

    ids_logs_global = [str(getattr(l, 'event_id', '')) for l in jeu.logs]

    # --- mesure au grain de la FENÊTRE (100 logs) ---
    #     Une fenêtre est « falsifiée » si elle contient au moins un log
    #     falsifié, « signalée » si elle contient au moins une annotation.
    #     C'est le grain auquel un analyste travaille : il ne cherche pas
    #     LE log manipulé, il cherche la ZONE du journal à ne pas croire.
    W = 100
    ids_logs = [str(getattr(l, "event_id", "")) for l in jeu.logs]
    fen_falsifiees = fen_signalees = fen_total = 0
    tpf = fpf = fnf = tnf = 0
    for debut in range(0, len(ids_logs), W):
        bloc = set(ids_logs[debut:debut + W])
        fen_total += 1
        est_fals = bool(bloc & falsifies_ids)
        est_sign = bool(bloc & signales)
        fen_falsifiees += est_fals
        fen_signalees += est_sign
        if est_fals and est_sign:   tpf += 1
        elif est_sign:              fpf += 1
        elif est_fals:              fnf += 1
        else:                       tnf += 1
    pf = tpf / (tpf + fpf) if tpf + fpf else 0.0
    rf = tpf / (tpf + fnf) if tpf + fnf else 0.0
    f1f = 2 * pf * rf / (pf + rf) if pf + rf else 0.0
    print(f"\n      AU GRAIN DE LA FENÊTRE ({W} logs) — le grain de l'analyste")
    print(f"        {fen_total:,} fenêtres | {fen_falsifiees:,} contiennent "
          f"une falsification")
    print(f"        TP {tpf:,}  FP {fpf:,}  FN {fnf:,}  TN {tnf:,}")
    print(f"        Precision {pf:.3f} | Recall {rf:.3f} | F1 {f1f:.3f}")

    # ⚠️ QUELLE RÈGLE SATURE LES FENÊTRES SAINES ?
    #    Une précision basse au grain de la fenêtre avec TN = 0 signifie que
    #    TOUTE fenêtre non falsifiée est malgré tout signalée. Le chiffre
    #    global ne dit pas PAR QUOI. On ventile donc les faux positifs par
    #    règle : une règle qui apparaît dans la quasi-totalité des fenêtres
    #    saines est celle qui rend la mesure inexploitable, indépendamment
    #    des autres qui peuvent être parfaitement précises.
    fenetres_saines = []
    for debut in range(0, len(ids_logs), W):
        bloc = set(ids_logs[debut:debut + W])
        if not (bloc & falsifies_ids):
            fenetres_saines.append(bloc)
    if fenetres_saines:
        satur = Counter()
        for bloc in fenetres_saines:
            regles_bloc = set()
            for eid in bloc & signales:
                regles_bloc.update(regles_par_id.get(eid, []))
            for r in regles_bloc:
                satur[r] += 1
        n_saines = len(fenetres_saines)
        print(f"\n      FAUX POSITIFS PAR RÈGLE — sur les {n_saines} fenêtres "
              f"SAINES")
        print(f"        {'règle':22s} {'fenêtres':>9s} {'part':>7s}")
        for r, n in satur.most_common():
            print(f"        {r:22s} {n:>9,} {n/n_saines:>6.1%}")
        principal = satur.most_common(1)
        if principal and principal[0][1] / n_saines > 0.8:
            print(f"\n        → {principal[0][0]} sature à lui seul "
                  f"{principal[0][1]/n_saines:.0%} des fenêtres saines.")
            print(f"          C'est LUI qui plafonne la précision à "
                  f"{pf:.3f}, pas l'ensemble du dispositif.")
        detail_saturation = {r: {"fenetres": n, "part": round(n / n_saines, 4)}
                             for r, n in satur.items()}
    else:
        detail_saturation = {}
        print(f"\n      (aucune fenêtre saine — augmenter --zones pour en "
              f"créer)")

    # ⚠️ SUPPRESSION — MESURÉE PAR POSITION, POUR LES RÈGLES AUSSI.
    #    Un log supprimé n'existe plus : son event_id n'est dans aucune
    #    fenêtre, donc le croisement par identifiant ne le compte NI en
    #    détecté NI en total. Le « 0/275 » du tableau par type ne signifie
    #    donc pas « indétectable », mais « non mesuré » — la même erreur que
    #    celle commise plus tôt sur l'injection.
    #    On localise ici le TROU : le premier log encore présent après
    #    chaque suppression. La fenêtre qui le contient est celle où la
    #    suppression est observable.
    positions_trous = set()
    position_finale = {eid: i for i, eid in enumerate(ids_logs)}
    for e in jeu.ground_truth:
        if e.falsification_type.value != "suppression":
            continue
        idx = e.original_index
        if idx is None:
            continue
        for j in range(idx + 1, min(idx + 50, len(logs))):
            eid_suivant = str(getattr(logs[j], "event_id", ""))
            if eid_suivant in position_finale:
                positions_trous.add(position_finale[eid_suivant])
                break

    if positions_trous:
        tp_sup_r = fn_sup_r = 0
        for debut in range(0, len(ids_logs), W):
            fin = debut + W
            if not any(debut <= p < fin for p in positions_trous):
                continue
            bloc = set(ids_logs[debut:fin])
            if bloc & signales:
                tp_sup_r += 1
            else:
                fn_sup_r += 1
        rappel_sup_r = (tp_sup_r / (tp_sup_r + fn_sup_r)
                        if tp_sup_r + fn_sup_r else 0.0)
        print(f"\n      SUPPRESSION — mesurée PAR POSITION du trou (règles)")
        print(f"        {len(positions_trous)} trou(s) localisé(s) | "
              f"{tp_sup_r + fn_sup_r} fenêtre(s) concernée(s)")
        print(f"        détectées par les règles : {tp_sup_r} "
              f"(rappel {rappel_sup_r:.3f})")
        detail_types["suppression_par_position"] = {
            "detectees": tp_sup_r, "total": tp_sup_r + fn_sup_r,
            "rappel": round(rappel_sup_r, 4),
            "methode": "position du trou — l'id supprimé n'existe plus"}

    # --- [D] AUTOENCODEUR : détection par PROFIL DE FENÊTRE ---------------
    #     Les règles détectent des INCOHÉRENCES ; l'autoencodeur détecte des
    #     DÉFORMATIONS DE PROFIL. Une injection ne crée aucune incohérence —
    #     c'est pourquoi les règles la manquent — mais elle modifie les
    #     ratios et le rythme de la fenêtre, ce que le modèle mesure.
    # ⚠️ Association id → type de falsification, DIRECTEMENT depuis
    #    `entree.event_id`. L'ancienne méthode associait par POSITION après
    #    un tri alphabétique de `falsifies_ids` (`ids_ordonnes[k]`), en
    #    supposant que le k-ième id trié correspondait au k-ième élément de
    #    `ground_truth` — FAUX, un tri alphanumérique n'a aucune raison de
    #    respecter l'ordre de génération. Conséquence détectée : le calcul
    #    affichait 0 injection manquée par les règles à examiner, alors que
    #    le tableau par type (section [A], basé sur un appariement correct)
    #    mesurait bien 235/235 manquées. `GroundTruthEntry.event_id` a donc
    #    été ajouté au générateur — c'est la source de vérité, pas un tri.
    type_par_id = {entree.event_id: entree.falsification_type.value
                  for entree in jeu.ground_truth if entree.event_id}
    if len(type_par_id) < len(jeu.ground_truth):
        print(f"      ⚠️ {len(jeu.ground_truth) - len(type_par_id)} entrée(s) "
              f"de vérité terrain sans event_id (génération antérieure à la "
              f"correction) — exclues de l'analyse par type.")

    injections_manquees_regles = {
        i for i, t in type_par_id.items()
        if t == "injection" and i not in signales}

    ae_resultat = {}
    try:
        import os
        if modele_ae and config_ae:
            # ⚠️ Modèle EXPLICITE (ex: collect_autoencoder_v3, celui qui
            #    généralise dans le temps sur Real Environment — voir
            #    documentation/AUTOENCODEUR_GENERALISATION_TEMPORELLE.md).
            #    Ne PAS repasser par charger_evaluateur(), qui pointe vers
            #    l'ancien modèle par défaut : on veut ici comparer les DEUX,
            #    pas écraser le comportement standard du système.
            from model_loader import load_collect_autoencoder
            from collect_agent.window_integrity import EvaluateurFenetre
            ae = load_collect_autoencoder(modele_ae, config_ae)
            taille = getattr(ae, "window_size", None) or 50
            ev = EvaluateurFenetre(ae, taille=taille)
            print(f"      autoencodeur : {modele_ae} (modèle EXPLICITE)")
        else:
            from collect_agent.window_integrity import charger_evaluateur
            racine = os.path.join(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))), "models")
            ev = charger_evaluateur("windows", racine=racine)
            print(f"      autoencodeur : modèle par défaut (models/)")

        # ⚠️ CALIBRATION SUR LE CORPUS DE DÉPLOIEMENT, AVANT MESURE.
        #    Le seuil livré avec le modèle vient de ses données
        #    d'entraînement (COMISET Real). Appliqué au Lab, il vaut 0,0239
        #    alors que l'erreur médiane sur des fenêtres SAINES y est de
        #    5,71 — 240 fois plus. D'où 100 % de faux positifs et TN = 0.
        #
        #    On recalibre sur `logs`, le corpus AVANT falsification : il est
        #    intègre par construction, c'est donc l'échantillon sain
        #    légitime. Le modèle n'est pas modifié, seul son seuil de
        #    décision est ramené dans son domaine de validité.
        ancien_seuil = ev.seuil
        nouveau_seuil = ev.calibrer(logs, percentile=95.0)
        print(f"      seuil recalibré sur le corpus sain : "
              f"{ancien_seuil:.4f} → {nouveau_seuil:.4f} "
              f"(95e percentile des erreurs saines)")

        verdicts_ae = ev.evaluer(jeu.logs)
        echecs = [v for v in verdicts_ae if v.get("echec")]
        if echecs:
            print(f"\n  [D] AUTOENCODEUR — indisponible : {echecs[0]['echec']}")
        else:
            tpa = fpa = fna = tna = 0
            par_type_ae = defaultdict(lambda: [0, 0])   # [détectées, total]
            for v in verdicts_ae:
                bloc = set(ids_logs_global[v["debut"]:v["fin"]])
                ids_falsifies_dans_bloc = bloc & falsifies_ids
                fals = bool(ids_falsifies_dans_bloc)
                sus = bool(v.get("suspect"))
                if fals and sus:   tpa += 1
                elif sus:          fpa += 1
                elif fals:         fna += 1
                else:              tna += 1
                for fid in ids_falsifies_dans_bloc:
                    t = type_par_id.get(fid)
                    if t:
                        par_type_ae[t][1] += 1
                        if sus:
                            par_type_ae[t][0] += 1

            pa = tpa / (tpa + fpa) if tpa + fpa else 0.0
            ra = tpa / (tpa + fna) if tpa + fna else 0.0
            f1a = 2 * pa * ra / (pa + ra) if pa + ra else 0.0
            print(f"\n  [D] AUTOENCODEUR — profil de fenêtre "
                  f"({ev.taille} logs, seuil {ev.seuil})")
            print(f"        {len(verdicts_ae)} fenêtres | "
                  f"TP {tpa} FP {fpa} FN {fna} TN {tna}")
            print(f"        Precision {pa:.3f} | Recall {ra:.3f} | F1 {f1a:.3f}")

            print(f"\n        DÉTECTION PAR TYPE (fenêtres contenant CE type)")
            detail_ae_type = {}
            for t, (d, n) in sorted(par_type_ae.items()):
                r = d / n if n else 0.0
                detail_ae_type[t] = {"detectees": d, "total": n, "rappel": round(r, 4)}
                print(f"          {t:16s} {d:>4}/{n:<4}  rappel {r:.3f}")

            # ⚠️ LA SUPPRESSION SE MESURE PAR POSITION, PAS PAR IDENTIFIANT.
            #    Un log supprimé n'existe plus dans le corpus falsifié : son
            #    event_id n'appartient à AUCUNE fenêtre, donc le croisement
            #    par identifiant (ci-dessus) ne le compte ni en détecté ni en
            #    total — il disparaît simplement du tableau.
            #
            #    Ce n'est pas « la suppression est indétectable ». C'est
            #    « la suppression n'était pas mesurée ». On repère donc la
            #    POSITION du trou dans le corpus final : le log qui SUIT
            #    immédiatement chaque suppression. La fenêtre qui le contient
            #    est celle où la suppression est visible.
            positions_trous = set()
            supprimes = {e.event_id for e in jeu.ground_truth
                        if e.falsification_type.value == "suppression"
                        and e.event_id}
            if supprimes:
                # ids du corpus final, dans l'ordre — un trou se situe là où
                # un id du corpus ORIGINAL manque
                ids_finaux = ids_logs_global
                position_finale = {eid: i for i, eid in enumerate(ids_finaux)}
                for e in jeu.ground_truth:
                    if e.falsification_type.value != "suppression":
                        continue
                    idx = e.original_index
                    if idx is None:
                        continue
                    # chercher le premier log ORIGINAL après idx encore présent
                    for j in range(idx + 1, min(idx + 50, len(logs))):
                        eid_suivant = logs[j].event_id
                        if eid_suivant in position_finale:
                            positions_trous.add(position_finale[eid_suivant])
                            break

                tp_sup = fn_sup = 0
                for v in verdicts_ae:
                    a_trou = any(v["debut"] <= p < v["fin"] for p in positions_trous)
                    if not a_trou:
                        continue
                    if v.get("suspect"):
                        tp_sup += 1
                    else:
                        fn_sup += 1
                rappel_sup = tp_sup / (tp_sup + fn_sup) if tp_sup + fn_sup else 0.0
                print(f"\n        SUPPRESSION — mesurée PAR POSITION du trou")
                print(f"          {len(supprimes)} log(s) supprimé(s), "
                      f"{len(positions_trous)} position(s) de trou localisée(s)")
                print(f"          fenêtres contenant un trou : {tp_sup + fn_sup}")
                print(f"          détectées par l'autoencodeur : {tp_sup} "
                      f"(rappel {rappel_sup:.3f})")
                detail_ae_type["suppression"] = {
                    "detectees": tp_sup, "total": tp_sup + fn_sup,
                    "rappel": round(rappel_sup, 4),
                    "methode": "par position du trou (l'id supprimé n'existe "
                               "plus dans le corpus)"}

            # --- LA question posée : l'autoencodeur rattrape-t-il les
            #     injections que les RÈGLES ont manquées ? ---
            n_rattrapees = n_examinees = 0
            taux_rattrapage = None
            if injections_manquees_regles:
                for v in verdicts_ae:
                    bloc = set(ids_logs_global[v["debut"]:v["fin"]])
                    if bloc & injections_manquees_regles:
                        n_examinees += 1
                        if v.get("suspect"):
                            n_rattrapees += 1
                taux_rattrapage = n_rattrapees / n_examinees if n_examinees else 0.0
                print(f"\n        ⚠️ INJECTIONS MANQUÉES PAR LES RÈGLES "
                      f"({len(injections_manquees_regles)} logs)")
                print(f"           fenêtres concernées : {n_examinees}")
                print(f"           rattrapées par l'autoencodeur : "
                      f"{n_rattrapees}/{n_examinees} ({taux_rattrapage:.1%})")
                if taux_rattrapage > 0.5:
                    print(f"           → OUI : l'autoencodeur voit ce que les")
                    print(f"             règles manquent. Les deux étages sont")
                    print(f"             COMPLÉMENTAIRES, pas redondants.")
                elif taux_rattrapage > 0:
                    print(f"           → PARTIEL : rattrapage incomplet.")
                else:
                    print(f"           → NON : l'autoencodeur ne rattrape pas")
                    print(f"             non plus l'injection sur ce corpus.")
            else:
                print(f"\n        (aucune injection manquée par les règles à "
                      f"tester)")

            ae_resultat = {"n_fenetres": len(verdicts_ae), "taille": ev.taille,
                           "TP": tpa, "FP": fpa, "FN": fna, "TN": tna,
                           "precision": round(pa, 4), "recall": round(ra, 4),
                           "f1": round(f1a, 4), "par_type": detail_ae_type,
                           "injections_manquees_regles": {
                               "n_logs": len(injections_manquees_regles),
                               "n_fenetres_examinees": n_examinees,
                               "n_rattrapees": n_rattrapees,
                               "taux_rattrapage": round(taux_rattrapage, 4)
                                                 if taux_rattrapage is not None else None,
                           }}
    except Exception as e:
        print(f"\n  [D] AUTOENCODEUR — non évalué : {str(e)[:90]}")

    return {"n_logs": len(jeu.logs), "n_falsifies": len(falsifies_ids),
            "autoencodeur": ae_resultat,
            "par_fenetre": {"taille": W, "n_fenetres": fen_total,
                            "TP": tpf, "FP": fpf, "FN": fnf, "TN": tnf,
                            "precision": round(pf, 4), "recall": round(rf, 4),
                            "f1": round(f1f, 4),
                            "saturation_fenetres_saines": detail_saturation},
            "TP": tp, "FP": fp, "FN": fn, "TN": tn,
            "precision": round(precision, 4), "recall": round(rappel, 4),
            "f1": round(f1, 4),
            "par_type": detail_types, "par_regle": detail_regles,
            "regles_inactives": sorted(inactives),
            "n_gaps": len(sorties.gaps)}


# =============================================================================
def mesurer_propagation() -> dict:
    """
    [C] — la falsification change-t-elle la DÉCISION ?

    ⚠️ C'est la mesure décisive de cette expérience. La règle R2 du Decision
    Agent stipule qu'une menace modérée accompagnée d'une falsification
    devient une menace CONFIRMÉE. Cette règle ne vaut que si le signal
    d'intégrité parvient jusqu'à la décision.
    """
    from decision_agent.signal_normalizers import normalize_all
    from decision_agent.correlator import Correlator
    from decision_agent.certainty_evaluator import CertaintyEvaluator

    print(f"\n  [C] PROPAGATION — la falsification change-t-elle la décision ?")

    menace = [{"host": "E3-HOTE", "attack_score": 0.72, "is_attack": True,
               "techniques": ["T1070"], "sequence_id": "E3",
               "sequence_summary": {"external_ips": []},
               "hypothesis": "effacement de traces"}]
    falsif = [["E3-HOTE", "tampering_rule: [R1_timestomping] horodatage 1970", 0.9],
              ["E3-HOTE", "gap: 8697 enregistrements manquants", 0.9]]

    resultats = {}
    for libelle, flags in (("menace SEULE", None),
                           ("menace + FALSIFICATION", falsif)):
        signaux = normalize_all(threat_verdicts=menace,
                                integrity_flags=flags) if flags \
            else normalize_all(threat_verdicts=menace)
        entites = Correlator().correlate(signaux)
        if not entites:
            continue
        d = CertaintyEvaluator().evaluate(entites[0])
        resultats[libelle] = {
            "certitude": d.certainty.value,
            "regles": list(d.triggered_rules),
            "escalade": bool(d.escalate),
            "signaux_integrite": len(entites[0].integrity_signals),
        }
        print(f"      {libelle:26s} → {d.certainty.value:10s} "
              f"{d.triggered_rules}")

    seule = resultats.get("menace SEULE", {}).get("certitude")
    avec = resultats.get("menace + FALSIFICATION", {}).get("certitude")
    effet = (seule != avec)
    print(f"\n      → la falsification {'CHANGE' if effet else 'ne change PAS'} "
          f"la décision ({seule} → {avec})")
    if effet:
        print(f"        La règle R2 est opérationnelle : une menace sous le")
        print(f"        seuil de confirmation (0.72 < 0.85) devient confirmée")
        print(f"        parce que les journaux portent des traces d'effacement.")
    return {"comparaison": resultats, "effet_sur_decision": effet}


# =============================================================================
def main() -> None:
    p = argparse.ArgumentParser(description="E3 — robustesse aux falsifications")
    p.add_argument("--csv", required=True, help="comiset_travail.csv")
    p.add_argument("--n", type=int, default=20000,
                   help="nombre de logs authentiques à falsifier")
    p.add_argument("--taux", type=float, default=0.05,
                   help="proportion de logs falsifiés")
    p.add_argument("--json", default="E3_robustesse_integrite.json")
    p.add_argument("--zones", type=int, default=0,
                   help="falsifier N zones CONTIGUËS au lieu de disperser. "
                        "Indispensable pour mesurer un vrai taux de faux "
                        "positifs : en mode dispersé, presque toutes les "
                        "fenêtres sont falsifiées (TN=0) et la précision est "
                        "mécaniquement gonflée. Recommandé : 5 à 10.")
    p.add_argument("--modele-ae", default=None,
                   help="chemin du modèle .pt à tester (défaut : celui de "
                        "models/, l'original qui sature à 100%%)")
    p.add_argument("--config-ae", default=None,
                   help="chemin de la config .pkl associée à --modele-ae")
    args = p.parse_args()

    if not os.path.exists(args.csv):
        print(f"  fichier introuvable : {args.csv}")
        sys.exit(1)

    print("=" * 70)
    print("  E3 — ROBUSTESSE AUX FALSIFICATIONS DE JOURNAUX")
    print("=" * 70)
    print("  Mesure la détection de MANIPULATION DES PREUVES, distincte de")
    print("  la détection d'attaque évaluée en E2.")

    print(f"\n  chargement de {args.n:,} logs authentiques…")
    logs = charger_logs_authentiques(args.csv, args.n)
    print(f"      {len(logs):,} logs mappés depuis {args.csv}")
    if len(logs) < 100:
        print("      corpus insuffisant.")
        sys.exit(1)

    detection = mesurer_detection(logs, args.taux, modele_ae=args.modele_ae,
                                  config_ae=args.config_ae, zones=args.zones)
    try:
        propagation = mesurer_propagation()
    except ModuleNotFoundError as e:
        # ⚠️ `decision_agent` appartient à l'agent Decision, absent du
        #    conteneur `agentic-collect` où ce script tourne souvent (c'est
        #    là que se trouve torch pour l'autoencodeur). Les sections [A],
        #    [B] et [D], qui concernent Collect, ont déjà produit leur
        #    résultat avant ce point — ne pas les perdre pour une section
        #    optionnelle qui a son propre conteneur d'exécution naturel.
        print(f"\n  [C] PROPAGATION — ignorée : {e} "
              f"(module de l'agent Decision, exécuter ce test "
              f"depuis agentic-decision pour l'obtenir)")
        propagation = {"comparaison": {}, "effet_sur_decision": None}

    print(f"\n{'=' * 70}\n  SYNTHÈSE E3\n{'=' * 70}")

    # ⚠️ LA MÉTRIQUE DE RÉFÉRENCE EST CELLE AU GRAIN DE LA FENÊTRE.
    #    Au grain du LOG, la précision est structurellement sous-évaluée :
    #    une falsification CONTAMINE ses voisins (déplacer un log rend
    #    anormaux tous les suivants, R5 les signale légitimement) et ces
    #    signalements sont comptés « faux positifs » alors qu'ils sont
    #    l'effet attendu d'une manipulation réelle. Mesuré : 0.061 au grain
    #    du log contre 0.975 au grain de la fenêtre, sur les mêmes données.
    #
    #    Le grain de la fenêtre est aussi celui du travail réel : un analyste
    #    cherche la ZONE du journal à ne pas croire, pas l'événement exact
    #    qui a été modifié.
    fen = detection.get("par_fenetre") or {}
    if fen:
        print(f"    RÉFÉRENCE — grain de la FENÊTRE ({fen.get('taille', 100)} logs) :")
        print(f"      Recall {fen.get('recall', 0):.3f} | "
              f"Precision {fen.get('precision', 0):.3f} | "
              f"F1 {fen.get('f1', 0):.3f}")
    print(f"\n    grain du LOG (précision sous-évaluée par la contamination")
    print(f"    des voisins, voir note) :")
    print(f"      Recall {detection['recall']:.3f} | "
          f"Precision {detection['precision']:.3f} | "
          f"F1 {detection['f1']:.3f}")

    # --- rappel par type, en combinant les deux grains ------------------
    print(f"\n    RAPPEL PAR TYPE DE FALSIFICATION")
    types_log = detection.get("par_type") or {}
    sup = types_log.get("suppression_par_position") or {}
    ae_types = (detection.get("autoencodeur") or {}).get("par_type") or {}
    for t in ("injection", "modification", "reordering"):
        r_regles = types_log.get(t, {}).get("rappel")
        r_ae = ae_types.get(t, {}).get("rappel")
        print(f"      {t:14s} règles {r_regles if r_regles is not None else '—':>6} "
              f"| autoencodeur {r_ae if r_ae is not None else '—':>6}")
    r_ae_sup = ae_types.get("suppression", {}).get("rappel")
    print(f"      {'suppression':14s} règles "
          f"{sup.get('rappel', '—'):>6} | autoencodeur "
          f"{r_ae_sup if r_ae_sup is not None else '—':>6}   (par position)")

    print(f"\n    effet sur la décision      : "
          f"{'OUI (règle R2 active)' if propagation['effet_sur_decision'] else 'non mesuré ici'}")

    print(f"\n  RÉSERVES À DÉCLARER")
    print(f"    · les falsifications sont INJECTÉES, non observées : ces")
    print(f"      chiffres mesurent la détection des falsifications")
    print(f"      MODÉLISÉES, pas de toutes celles qu'un attaquant réel")
    print(f"      pourrait pratiquer ;")
    print(f"    · les types couverts sont : modification, suppression,")
    print(f"      réordonnancement, injection — un effacement propre via")
    print(f"      l'API Windows ne laisserait pas les mêmes traces ;")
    print(f"    · la SUPPRESSION n'est mesurable qu'au grain de la fenêtre :")
    print(f"      un log supprimé n'existe plus, aucune annotation ne peut")
    print(f"      lui être attachée — d'où sa mesure par POSITION du trou ;")
    print(f"    · si le corpus est trié par record_number, l'ordre")
    print(f"      chronologique peut être rompu (58,9 % de reculs mesurés")
    print(f"      sur COMISET Lab) et R5_out_of_order s'en trouve dégradé ;")
    print(f"    · le corpus source est COMISET, dont les logs sont eux-mêmes")
    print(f"      supposés intègres — hypothèse non vérifiable.")

    with open(args.json, "w", encoding="utf-8") as f:
        json.dump({"detection": detection, "propagation": propagation,
                   "parametres": {"n_logs": args.n, "taux": args.taux}},
                  f, ensure_ascii=False, indent=2)
    print(f"\n  résultats exportés : {args.json}")


if __name__ == "__main__":
    main()
