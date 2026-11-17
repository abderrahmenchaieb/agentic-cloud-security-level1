"""
=============================================================================
E0 — REPRODUCTIBILITÉ
=============================================================================
Le système donne-t-il le MÊME résultat sur des exécutions identiques ?

⚠️ POURQUOI CETTE EXPÉRIENCE VIENT EN PREMIER
    Le système comporte plusieurs facteurs temporels susceptibles de faire
    diverger deux runs pourtant identiques :

      · fenêtre de corrélation de 300 s — un signal peut expirer entre deux
        cycles selon l'instant où il est arrivé ;
      · traitement asynchrone d'Analysis — l'ordre d'arrivée des verdicts
        chez Decision n'est pas garanti ;
      · latence variable d'Ollama sur CPU (30 à 100 s par lot) ;
      · cache de séquences borné à 50 entrées ;
      · construction du graphe d'E-GraphSAGE, dont le verdict dépend du
        voisinage — donc de l'ensemble du lot reçu.

    Si les résultats varient d'un run à l'autre, AUCUNE des expériences
    suivantes n'est publiable : on ne pourrait pas distinguer l'effet d'un
    paramètre de la simple variabilité du système.

    Un reviewer posera la question. Mieux vaut y répondre par une mesure.

CE QUI EST COMPARÉ
    Les grandeurs qui doivent être STABLES pour un même scénario :
      entités suivies, confirmées, en investigation, escaladées.

    La durée n'est PAS un critère : elle dépend de la charge machine et de
    la latence du LLM, qui varient légitimement.

USAGE
    python3 E0_reproductibilite.py                      3 répétitions
    python3 E0_reproductibilite.py --n 5                davantage
    python3 E0_reproductibilite.py --sans-llm           écarte la variabilité
                                                        d'Ollama
    python3 E0_reproductibilite.py --csv Darknet.csv    trafic de fond réel
=============================================================================
"""
from __future__ import annotations

import argparse
import os
import statistics
import sys

_ICI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _ICI)

from campagne import Campagne, etat_propre, AGENTS, BUS_URL, _get


def _executer_scenario(csv: str | None, fond: int):
    """Rejoue le scénario global — celui qui sollicite le plus le système."""
    def _run():
        import scenario_global as sg
        base_flux = sg.flux_du_parc(fond, csv)
        sg.post(f"{sg.ANON_URL}/ingest",
                {"flows": base_flux, "source": "E0"})

        import time
        from datetime import datetime, timedelta, timezone
        time.sleep(2)
        base = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=20)
        h = sg._Horloge(base)
        for generateur in (sg.hote_compromis_hameconnage,
                           sg.hote_vol_identifiants,
                           sg.hote_exfiltration_effacement,
                           sg.hote_sain):
            sg.post(f"{sg.COLLECT_URL}/ingest", {"events": generateur(h)})
            time.sleep(1)
        sg.post(f"{sg.COLLECT_URL}/ingest",
                {"events": sg.compte_aws_compromis(base - timedelta(hours=3)),
                 "source": "cloudtrail"})
    return _run


def main() -> None:
    p = argparse.ArgumentParser(description="E0 — reproductibilité")
    p.add_argument("--n", type=int, default=3, help="nombre de répétitions")
    p.add_argument("--csv", help="CSV brut de CIC-Darknet2020")
    p.add_argument("--fond", type=int, default=3000)
    p.add_argument("--sans-llm", action="store_true",
                   help="rappel : l'agent doit être démarré avec ENABLE_LLM=0")
    args = p.parse_args()

    print("=" * 70)
    print("  E0 — REPRODUCTIBILITÉ")
    print("=" * 70)
    print(f"  {args.n} exécutions identiques du scénario global")
    print(f"  trafic de fond : {args.fond} flux"
          f"{' (CSV réel)' if args.csv else ' (distributions du dataset)'}")

    # l'état du LLM conditionne l'interprétation : on le relève
    sante = _get(f"{AGENTS['analysis']}/health") or {}
    llm = sante.get("llm")
    print(f"  LLM : {'actif' if llm else 'désactivé'}"
          f"{'  — sa latence variable ajoute du bruit' if llm else ''}")

    if not _get(f"{BUS_URL}/health"):
        print("\n  système injoignable — démarrer la pile d'abord.")
        sys.exit(1)

    campagne = Campagne()
    executer = _executer_scenario(args.csv, args.fond)
    for i in range(args.n):
        campagne.experience(f"E0 — répétition {i + 1}/{args.n}", executer)

    if len(campagne.resultats) < 2:
        print("\n  pas assez d'exécutions abouties pour conclure.")
        sys.exit(1)

    # --- comparaison ---------------------------------------------------
    cles = ("entites_suivies", "confirmees", "en_investigation", "escaladees")
    valeurs = {k: [r.get("resume_decision", {}).get(k, 0)
                   for r in campagne.resultats] for k in cles}
    durees = [r["duree_s"] for r in campagne.resultats]

    print(f"\n{'=' * 70}\n  RÉSULTAT DE E0\n{'=' * 70}")
    print(f"  {'grandeur':22s} {'valeurs':28s} verdict")
    print("  " + "-" * 62)
    stable = True
    for k, v in valeurs.items():
        identique = len(set(v)) == 1
        stable = stable and identique
        print(f"  {k:22s} {str(v):28s} "
              f"{'identique' if identique else 'VARIABLE'}")

    print(f"\n  durées : {[f'{d:.0f}s' for d in durees]}")
    if len(durees) > 1:
        print(f"    écart-type {statistics.stdev(durees):.0f}s "
              f"— la durée n'est pas un critère de reproductibilité "
              f"(charge machine, latence LLM)")

    print()
    if stable:
        print("  → REPRODUCTIBLE. Les expériences E1 à E5 peuvent être menées :")
        print("    une variation observée entre deux configurations pourra être")
        print("    attribuée au paramètre modifié, non au bruit du système.")
    else:
        variables = [k for k, v in valeurs.items() if len(set(v)) > 1]
        print(f"  → NON REPRODUCTIBLE sur : {', '.join(variables)}")
        print()
        print("    Les mesures suivantes seraient ininterprétables : on ne")
        print("    pourrait pas distinguer l'effet d'un paramètre de la")
        print("    variabilité propre au système.")
        print()
        print("    Pistes, par ordre de probabilité :")
        print("      · LLM actif → sa latence décale les cycles de décision ;")
        print("        reprendre avec ENABLE_LLM=0 pour l'écarter ;")
        print("      · fenêtre de corrélation → un signal expire ou non selon")
        print("        l'instant d'arrivée ; allonger CORRELATION_WINDOW ;")
        print("      · attente insuffisante → un run mesuré avant la fin du")
        print("        traitement produit des chiffres partiels.")

    campagne.rapport()
    campagne.exporter("E0_reproductibilite.json")


if __name__ == "__main__":
    main()
