"""
=============================================================================
TEST DE GÉNÉRALISATION BRUTE — modèle Lab sur données Real (indicatif)
=============================================================================
⚠️ CE N'EST PAS UNE MESURE PUBLIABLE
    Échantillon réduit (20 001 lignes), concentré sur 1 à 7 hôtes, 2 jours
    seulement, très majoritairement EventID 10 (ProcessAccess). C'est un
    INDICATEUR PRÉCOCE avant la mesure complète sur Real Environment
    correctement échantillonné.

CE QUE CE SCRIPT FAIT
    Convertit extrait_milieu.txt et extrait_fin.txt (format JSON Elastic)
    vers le format Sysmon attendu par le pipeline, sans aucun réentraînement,
    puis fait tourner le détecteur Windows (RandomForest) actuel — celui
    entraîné sur Lab — pour voir comment il se comporte sur un environnement
    qu'il n'a jamais vu.

    L'autoencodeur n'est PAS testé ici : torch est indisponible dans cet
    environnement. À faire séparément, dans le conteneur `agentic-collect`.
=============================================================================
"""
from __future__ import annotations

import json
import os
import sys
from collections import Counter, defaultdict

_ICI = os.path.dirname(os.path.abspath(__file__))
_RACINE = os.path.dirname(_ICI)
for chemin in (_ICI, _RACINE,
               os.path.join(_RACINE, "agents", "1_collect_agent"),
               os.path.join(_RACINE, "agents", "2_analysis_agent")):
    if chemin not in sys.path:
        sys.path.insert(0, chemin)


# =============================================================================
def convertir_ligne_real(doc: dict) -> dict | None:
    """
    Convertit un document Elastic (format Real) vers le format Sysmon plat
    attendu par `sysmon_mapper.map_sysmon_event`.

    ⚠️ MAPPING ÉTABLI PAR INSPECTION DIRECTE (pas deviné) :
        event_id            → EventID
        @timestamp           → UtcTime
        host_name             → Computer (le suffixe .domain.es est conservé,
                               il n'affecte pas le mapper)
        process_guid           → ProcessGuid
        process_path/name       → Image
        rule_technique_id        → vérité terrain (conservée à part, "_verite")

    Les champs spécifiques à l'EventID (TargetProcessGUID pour le 8,
    DestinationIp pour le 3...) ne sont PAS encore confirmés sur des
    exemples réels de ces EventID — absents des extraits disponibles
    (dominés par l'EventID 10). Ils sont ajoutés au mieux, sans garantie.
    """
    src = doc.get("_source")
    if not isinstance(src, dict):
        return None

    horodatage = (src.get("@timestamp") or src.get("event_original_time") or "").strip()
    if not horodatage:
        return None
    horodatage = horodatage.replace("T", " ").replace("Z", "")
    if "." not in horodatage:
        horodatage += ".000"

    evt = {
        "EventID": str(src.get("event_id") or "").strip(),
        "UtcTime": horodatage[:23],
        "Computer": (src.get("host_name") or "inconnu").strip(),
        "ProcessGuid": (src.get("process_guid") or "").strip(),
        "Image": (src.get("process_path") or src.get("process_name") or "").strip(),
        "_verite": bool(src.get("rule_technique_id")),
        "_technique": src.get("rule_technique_id") or "",
        "_source_provider": src.get("source_name") or "",
    }
    # champs optionnels, si présents sous ces noms
    for cible, sources in (
        ("TargetProcessGuid", ("TargetProcessGUID", "target_process_guid")),
        ("TargetImage", ("TargetImage", "target_process_name")),
        ("ImageLoaded", ("ImageLoaded",)),
        ("DestinationIp", ("DestinationIp", "dest_ip")),
        ("TargetObject", ("TargetObject",)),
    ):
        for s in sources:
            if src.get(s):
                evt[cible] = src[s]
                break
    return evt


def charger_extrait(chemin: str) -> list[dict]:
    evenements = []
    with open(chemin, encoding="utf-8", errors="ignore") as f:
        for ligne in f:
            ligne = ligne.strip()
            if not ligne:
                continue
            try:
                doc = json.loads(ligne)
            except json.JSONDecodeError:
                continue
            evt = convertir_ligne_real(doc)
            if evt and evt["EventID"]:
                evenements.append(evt)
    return evenements


# =============================================================================
def main() -> None:
    print("=" * 70)
    print("  TEST INDICATIF — généralisation Lab → Real (échantillon réduit)")
    print("=" * 70)
    print("  ⚠️ Résultat NON publiable en l'état : échantillon petit et peu")
    print("     diversifié. Sert à détecter un problème AVANT la mesure")
    print("     complète, pas à la remplacer.\n")

    fichiers = sys.argv[1:] or ["extrait_milieu.txt", "extrait_fin.txt"]
    tous = []
    for f in fichiers:
        if not os.path.exists(f):
            print(f"  [!] introuvable : {f}")
            continue
        ev = charger_extrait(f)
        print(f"  {f:24s} → {len(ev):,} événements Sysmon convertis")
        tous.extend(ev)

    if not tous:
        print("\n  aucun événement chargé.")
        sys.exit(1)

    print(f"\n  total : {len(tous):,} événements")
    n_verite = sum(1 for e in tous if e["_verite"])
    print(f"  étiquetés attaque : {n_verite} ({n_verite/len(tous):.2%})")
    techniques = Counter(e["_technique"] for e in tous if e["_verite"])
    print(f"  techniques présentes : {dict(techniques)}")
    eids = Counter(e["EventID"] for e in tous)
    print(f"  EventID : {dict(eids.most_common(8))}")

    # --- séquençage et détection --------------------------------------
    from collect_agent.sysmon_mapper import map_sysmon_event
    from analysis_agent.sequence_builder import SequenceBuilder
    from service_analysis import logs_to_events, build_detector
    from service_collect import _serialize_log

    print(f"\n  conversion en CanonicalLog…")
    logs, verite_par_temps = [], {}
    for e in tous:
        brut = {k: v for k, v in e.items() if not k.startswith("_")}
        r = map_sysmon_event(brut, replay_mode=True)
        log = getattr(r, "log", None)
        if log is None:
            continue
        logs.append(log)
        cle = brut["UtcTime"]
        verite_par_temps[cle] = verite_par_temps.get(cle, False) or e["_verite"]
    print(f"  {len(logs):,}/{len(tous):,} logs acceptés par le mapper")
    if len(logs) < len(tous) * 0.5:
        print(f"  ⚠️ Plus de la moitié des logs REJETÉS par le mapper — le")
        print(f"     format Real diverge probablement du format attendu au")
        print(f"     delà de ce que ce script gère. À examiner avant toute")
        print(f"     mesure sérieuse.")

    ser = [_serialize_log(l) for l in logs]
    win, _ = logs_to_events(ser)
    print(f"  {len(win):,} Event Windows reconstruits")

    detecteur, voies = build_detector()
    print(f"  détecteur chargé : {voies} (entraîné sur Lab, INCHANGÉ)")

    seqs = SequenceBuilder().build(win)
    print(f"\n  {len(seqs)} séquence(s) construite(s)")

    y_vrai, y_pred, scores = [], [], []
    for seq in seqs:
        marques = []
        for ev in seq.events:
            t = getattr(ev, "event_time", None)
            if t is None:
                continue
            cle = t.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            if cle in verite_par_temps:
                marques.append(verite_par_temps[cle])
        attendu = int(any(marques))
        res = detecteur.predict(seq)
        score = float(getattr(res, "attack_score", 0.0) or 0.0)
        y_vrai.append(attendu)
        y_pred.append(int(bool(getattr(res, "is_attack", False))))
        scores.append(score)

    tp = sum(1 for a, p in zip(y_vrai, y_pred) if a == 1 and p == 1)
    fp = sum(1 for a, p in zip(y_vrai, y_pred) if a == 0 and p == 1)
    fn = sum(1 for a, p in zip(y_vrai, y_pred) if a == 1 and p == 0)
    tn = sum(1 for a, p in zip(y_vrai, y_pred) if a == 0 and p == 0)
    precision = tp / (tp + fp) if tp + fp else 0.0
    rappel = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0

    print(f"\n{'=' * 70}\n  RÉSULTAT INDICATIF\n{'=' * 70}")
    print(f"    TP {tp}  FP {fp}  FN {fn}  TN {tn}")
    print(f"    Precision {precision:.3f} | Recall {rappel:.3f} | FPR {fpr:.3f}")
    print(f"\n  RAPPEL : n={len(y_vrai)} séquences seulement.")
    print(f"    Un déséquilibre extrême (97 % d'EventID 10) et une seule")
    print(f"    technique dominante (T1055) rendent ce résultat FRAGILE.")
    print(f"    À confirmer sur le dataset Real complet et bien échantillonné.")

    if scores:
        scores.sort()
        print(f"\n  distribution des scores : min {scores[0]:.3f} "
              f"med {scores[len(scores)//2]:.3f} max {scores[-1]:.3f}")


if __name__ == "__main__":
    main()
