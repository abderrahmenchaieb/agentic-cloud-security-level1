"""
=============================================================================
E5 — PERFORMANCE ET PROPORTIONNALITÉ DE L'IA
=============================================================================
Combien coûte chaque étage, et l'IA coûteuse est-elle réservée aux cas qui
la justifient ?

⚠️ POURQUOI MESURER PAR ÉTAGE, ET NON EN BOUT DE CHAÎNE
    Le LLM (Ollama, CPU) prend 30 à 100 s par lot, contre quelques
    millisecondes pour les autres étages. Une mesure globale p50/p95/p99
    serait entièrement dominée par lui : les trois autres agents
    deviendraient invisibles, et le chiffre ne dirait rien d'exploitable.

    Chaque étage est donc chronométré SÉPARÉMENT, sur le même corpus.

⚠️ CE QUE « PROPORTIONNALITÉ » SIGNIFIE ICI
    L'architecture prévoit que l'IA la plus coûteuse ne soit sollicitée que
    lorsqu'elle apporte quelque chose. Concrètement, dans AnalysisAgent :

        if det.is_attack:               # ← le filtre
            interp = self.interpreter.interpret(seq)

    Le LLM n'interprète QUE les séquences déjà retenues par le détecteur.
    E5 mesure ce taux réel de sollicitation : si le détecteur retient 3 % des
    séquences, le LLM ne coûte que sur 3 % du volume.

    Un taux proche de 100 % signifierait que le filtre ne filtre rien et que
    l'architecture ne tient pas sa promesse.

QUATRE MESURES

  [A] LATENCE PAR ÉTAGE   p50 / p95 / p99 de chaque agent, séparément.
  [B] PROPORTIONNALITÉ    part des séquences envoyées au LLM, et coût évité.
  [C] DÉBIT               événements traités par seconde, par étage.
  [D] ABLATION            que perd-on en désactivant chaque composant ?

USAGE
    python3 services/E5_performance.py --csv comiset_travail.csv --n 20000
    python3 services/E5_performance.py --csv comiset_travail.csv --sans-llm
=============================================================================
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time

_ICI = os.path.dirname(os.path.abspath(__file__))
_RACINE = os.path.dirname(_ICI)
for chemin in (_ICI, _RACINE,
               os.path.join(_RACINE, "agents", "1_collect_agent"),
               os.path.join(_RACINE, "agents", "2_analysis_agent"),
               os.path.join(_RACINE, "agents", "4_decision_agent"),
               os.path.join(_RACINE, "cloud_adapter")):
    if chemin not in sys.path:
        sys.path.insert(0, chemin)


def _percentiles(durees: list[float]) -> dict:
    """p50/p95/p99 en millisecondes."""
    if not durees:
        return {}
    ordonnees = sorted(durees)
    def p(q):
        i = min(len(ordonnees) - 1, int(q * (len(ordonnees) - 1)))
        return round(ordonnees[i] * 1000, 3)
    return {"n": len(durees), "p50": p(0.50), "p95": p(0.95), "p99": p(0.99),
            "min": round(ordonnees[0] * 1000, 3),
            "max": round(ordonnees[-1] * 1000, 3),
            "moyenne": round(statistics.mean(durees) * 1000, 3),
            "total_s": round(sum(durees), 2)}


# =============================================================================
def charger(chemin: str, maximum: int) -> list[dict]:
    """Événements bruts au format Sysmon, sans traitement."""
    import csv
    evts = []
    with open(chemin, newline="", encoding="utf-8", errors="ignore") as f:
        for ligne in csv.DictReader(f):
            if len(evts) >= maximum:
                break
            h = (ligne.get("@timestamp") or "").strip()
            if not h:
                continue
            h = h.replace("T", " ").replace("Z", "")
            if "." not in h:
                h += ".000"
            eid = (ligne.get("event_id") or "").strip()
            if not eid:
                continue
            evts.append({
                "EventID": eid, "UtcTime": h[:23],
                "Computer": (ligne.get("host_name") or "?").strip(),
                "ProcessGuid": (ligne.get("process_guid") or "").strip(),
                "Image": (ligne.get("process_path")
                          or ligne.get("process_name") or "").strip(),
            })
    return evts


def mesurer_etages(evts: list[dict], lot: int = 500) -> dict:
    """[A] et [C] — chronométrage de chaque étage, séparément."""
    from collect_agent.collect_agent import CollectAgent, CollectOutputs
    from analysis_agent.analysis_agent import AnalysisAgent
    from service_collect import _serialize_log
    from service_analysis import logs_to_events, build_detector

    print(f"\n  [A] LATENCE PAR ÉTAGE — lots de {lot} événements")

    collect = CollectAgent(replay_mode=True)
    detecteur, voies = build_detector()
    # ⚠️ interpreter=None : on isole ici le coût du DÉTECTEUR seul.
    #    Le coût du LLM est mesuré séparément en [B], sinon il masquerait
    #    tout le reste (30-100 s contre quelques ms).
    analysis = AnalysisAgent(detector=detecteur, interpreter=None)

    d_collect, d_analysis = [], []
    n_seq = n_att = 0
    for debut in range(0, len(evts), lot):
        tranche = evts[debut:debut + lot]

        t0 = time.perf_counter()
        collect.outputs = CollectOutputs()
        sorties = collect.process_batch(tranche)
        d_collect.append(time.perf_counter() - t0)

        if not sorties.enriched:
            continue
        logs = [_serialize_log(e.log) for e in sorties.enriched]
        events, _ = logs_to_events(logs)
        if not events:
            continue

        t1 = time.perf_counter()
        res = analysis.analyze(events)
        d_analysis.append(time.perf_counter() - t1)
        n_seq += len(res.verdicts)
        n_att += sum(1 for v in res.verdicts if getattr(v, "is_attack", False))

    stats = {"collect": _percentiles(d_collect),
             "analysis_sans_llm": _percentiles(d_analysis)}
    for nom, s in stats.items():
        if s:
            print(f"      {nom:20s} p50 {s['p50']:>8.1f} ms | "
                  f"p95 {s['p95']:>8.1f} ms | p99 {s['p99']:>8.1f} ms")

    total = sum(d_collect) + sum(d_analysis)
    debit = len(evts) / total if total else 0
    print(f"\n  [C] DÉBIT")
    print(f"      {len(evts):,} événements en {total:.1f}s "
          f"→ {debit:,.0f} évén./s (hors LLM)")

    return {"latences": stats, "debit_par_seconde": round(debit, 1),
            "n_evenements": len(evts), "n_sequences": n_seq,
            "n_attaques": n_att, "voies": voies}


def mesurer_proportionnalite(n_seq: int, n_att: int,
                             cout_llm_s: float = 45.0) -> dict:
    """
    [B] Le LLM est-il réservé aux cas qui le justifient ?

    ⚠️ `cout_llm_s` est une ESTIMATION du coût d'une interprétation sur CPU
    (30-100 s observés). Le coût évité est donc un ORDRE DE GRANDEUR, pas
    une mesure — il dépend du matériel. Ce qui est mesuré exactement, c'est
    le TAUX de sollicitation, qui ne dépend que du système.
    """
    print(f"\n  [B] PROPORTIONNALITÉ DE L'IA COÛTEUSE")
    taux = n_att / n_seq if n_seq else 0.0
    print(f"      {n_seq:,} séquence(s) analysée(s)")
    print(f"      {n_att:,} retenue(s) par le détecteur "
          f"→ envoyées au LLM ({taux:.1%})")
    print(f"      {n_seq - n_att:,} écartée(s) sans appel au LLM "
          f"({1 - taux:.1%})")

    evite = (n_seq - n_att) * cout_llm_s
    print(f"\n      coût évité (à ~{cout_llm_s:.0f}s par interprétation) : "
          f"{evite / 60:,.0f} min")
    print(f"      ⚠️ ordre de grandeur — dépend du matériel ; le TAUX de "
          f"sollicitation,")
    print(f"         lui, est une propriété du système, indépendante de la "
          f"machine.")

    if taux > 0.5:
        print(f"\n      ⚠️ Plus de la moitié des séquences atteignent le LLM :")
        print(f"         le filtre `if det.is_attack` ne filtre plus grand")
        print(f"         chose. L'architecture ne tient pas sa promesse de")
        print(f"         proportionnalité sur ce corpus.")
    else:
        print(f"\n      → Le filtre `if det.is_attack` réserve l'IA coûteuse")
        print(f"        à {taux:.1%} du volume.")
    return {"n_sequences": n_seq, "n_envoyees_llm": n_att,
            "taux_sollicitation": round(taux, 4),
            "cout_evite_estime_min": round(evite / 60, 1),
            "cout_llm_suppose_s": cout_llm_s}


def mesurer_ablation(evts: list[dict]) -> dict:
    """
    [D] Que perd-on en retirant chaque composant ?

    ⚠️ Mesure ce que chaque étage APPORTE, pas seulement ce qu'il coûte.
    Un composant coûteux qui ne change aucun verdict serait à retirer.
    """
    from collect_agent.collect_agent import CollectAgent, CollectOutputs
    from analysis_agent.analysis_agent import AnalysisAgent
    from service_collect import _serialize_log
    from service_analysis import logs_to_events, build_detector

    print(f"\n  [D] ABLATION — apport réel de chaque composant")
    detecteur, _ = build_detector()
    resultats = {}

    for libelle, replay in (("Collect avec replay_mode", True),
                            ("Collect sans replay_mode", False)):
        collect = CollectAgent(replay_mode=replay)
        collect.outputs = CollectOutputs()
        t0 = time.perf_counter()
        sorties = collect.process_batch(evts[:2000])
        duree = time.perf_counter() - t0
        n_annot = sum(1 for e in sorties.enriched
                      if getattr(e, "annotations", None))
        resultats[libelle] = {"duree_s": round(duree, 3),
                              "logs_annotes": n_annot,
                              "enrichis": len(sorties.enriched)}
        print(f"      {libelle:32s} {n_annot:>5,} log(s) annoté(s) "
              f"en {duree:.2f}s")

    ecart = (resultats["Collect sans replay_mode"]["logs_annotes"]
             - resultats["Collect avec replay_mode"]["logs_annotes"])
    if ecart > 0:
        print(f"\n      ⚠️ {ecart:,} annotation(s) de plus SANS replay_mode :")
        print(f"         ce sont des R3_clock_skew dus au rejeu de données")
        print(f"         anciennes, pas à de vraies falsifications. Le mode")
        print(f"         rejeu est donc INDISPENSABLE sur corpus archivé.")
    return resultats


# =============================================================================
def main() -> None:
    p = argparse.ArgumentParser(description="E5 — performance")
    p.add_argument("--csv", required=True)
    p.add_argument("--n", type=int, default=20000)
    p.add_argument("--lot", type=int, default=500)
    p.add_argument("--cout-llm", type=float, default=45.0,
                   help="coût supposé d'une interprétation LLM, en secondes")
    p.add_argument("--json", default="E5_performance.json")
    args = p.parse_args()

    if not os.path.exists(args.csv):
        print(f"  fichier introuvable : {args.csv}")
        sys.exit(1)

    print("=" * 70)
    print("  E5 — PERFORMANCE ET PROPORTIONNALITÉ DE L'IA")
    print("=" * 70)

    print(f"\n  chargement de {args.n:,} événements…")
    evts = charger(args.csv, args.n)
    print(f"  {len(evts):,} événements chargés")

    etages = mesurer_etages(evts, lot=args.lot)
    prop = mesurer_proportionnalite(etages["n_sequences"],
                                    etages["n_attaques"],
                                    cout_llm_s=args.cout_llm)
    ablation = mesurer_ablation(evts)

    print(f"\n{'=' * 70}\n  SYNTHÈSE E5\n{'=' * 70}")
    c = etages["latences"].get("collect", {})
    a = etages["latences"].get("analysis_sans_llm", {})
    if c:
        print(f"    Collect   p50 {c['p50']:.1f} ms | p95 {c['p95']:.1f} ms")
    if a:
        print(f"    Analysis  p50 {a['p50']:.1f} ms | p95 {a['p95']:.1f} ms "
              f"(hors LLM)")
    print(f"    Débit     {etages['debit_par_seconde']:,.0f} évén./s")
    print(f"    LLM       {prop['taux_sollicitation']:.1%} des séquences")

    print(f"\n  RÉSERVES")
    print(f"    · mesures hors conteneur, sur un seul processus : elles ne")
    print(f"      reflètent pas les latences réseau du déploiement Docker ;")
    print(f"    · le coût du LLM est ESTIMÉ, pas mesuré — seul le TAUX de")
    print(f"      sollicitation est une propriété du système ;")
    print(f"    · matériel non contrôlé : les latences absolues varient, les")
    print(f"      RAPPORTS entre étages sont plus robustes.")

    with open(args.json, "w", encoding="utf-8") as f:
        json.dump({"etages": etages, "proportionnalite": prop,
                   "ablation": ablation}, f, ensure_ascii=False, indent=2)
    print(f"\n  résultats exportés : {args.json}")


if __name__ == "__main__":
    main()
