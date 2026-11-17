"""
=============================================================================
AUTOENCODEUR SUR REAL — l'échec sur Lab était-il spécifique à l'extrait ?
=============================================================================
⚠️ RÉSULTAT DE RÉFÉRENCE, DÉJÀ MESURÉ SUR LE LAB
    Sur 20 000 logs SAINS extraits du DÉBUT de comiset_travail.csv :
    100 % des fenêtres signalées suspectes, erreur médiane 40.6 pour un
    seuil de 0.392 — l'autoencodeur ne discrimine RIEN sur cet extrait.
    Cause identifiée : des features à variance quasi nulle à l'entraînement
    (r_dll, r_process, r_network) explosent au moindre écart réel.

CE QUE CE SCRIPT VÉRIFIE
    Le même phénomène se reproduit-il sur un environnement TOTALEMENT
    différent (Real Environment), ou était-il spécifique à la zone du Lab
    utilisée dans le premier test ?

    Si Real sature aussi massivement : la cause est structurelle (le
    problème de représentativité de l'entraînement se manifeste partout).
    Si Real NE sature PAS : l'extrait du Lab était en cause, pas le modèle
    lui-même — et il faudrait retester le Lab sur un échantillon plus large
    avant de conclure quoi que ce soit sur l'autoencodeur.

⚠️ RÉSERVE — ÉCHANTILLON RÉDUIT
    20 001 fenêtres possibles au mieux (20 001 logs / 50), en pratique
    beaucoup moins car les logs rejetés par le mapper cassent la continuité.
    Résultat INDICATIF, à confirmer sur un passage plus large.

USAGE (dans le conteneur agentic-collect, qui a torch)
    docker cp extrait_milieu.txt agentic-collect:/tmp/
    docker cp extrait_fin.txt agentic-collect:/tmp/
    docker cp services/test_autoencodeur_real.py agentic-collect://app/services/
    docker cp services/test_indicatif_real.py agentic-collect://app/services/
    docker cp agents/1_collect_agent/collect_agent/window_integrity.py \
        agentic-collect://app/agents/1_collect_agent/collect_agent/
    docker exec agentic-collect sh -c \
        "python /app/services/test_autoencodeur_real.py /tmp/extrait_milieu.txt /tmp/extrait_fin.txt"
=============================================================================
"""
from __future__ import annotations

import os
import sys

_ICI = os.path.dirname(os.path.abspath(__file__))
_RACINE = os.path.dirname(_ICI)
for chemin in (_ICI, _RACINE,
               os.path.join(_RACINE, "agents", "1_collect_agent"),
               os.path.join(_RACINE, "agents", "2_analysis_agent")):
    if chemin not in sys.path:
        sys.path.insert(0, chemin)


def main() -> None:
    print("=" * 70)
    print("  AUTOENCODEUR SUR REAL — comparaison avec l'échec mesuré sur Lab")
    print("=" * 70)

    from test_indicatif_real import charger_extrait
    from collect_agent.sysmon_mapper import map_sysmon_event
    from collect_agent.window_integrity import (charger_evaluateur,
                                                 fenetre_vers_scores, NOMS_SCORES)

    fichiers = sys.argv[1:] or ["/tmp/extrait_milieu.txt", "/tmp/extrait_fin.txt"]
    tous = []
    for f in fichiers:
        if not os.path.exists(f):
            print(f"  [!] introuvable : {f}")
            continue
        ev = charger_extrait(f)
        print(f"  {f:30s} → {len(ev):,} événements")
        tous.extend(ev)
    if not tous:
        sys.exit(1)

    print(f"\n  conversion en CanonicalLog…")
    logs = []
    for e in tous:
        brut = {k: v for k, v in e.items() if not k.startswith("_")}
        r = map_sysmon_event(brut, replay_mode=True)
        log = getattr(r, "log", None)
        if log is not None:
            logs.append(log)
    print(f"  {len(logs):,}/{len(tous):,} logs acceptés")

    print(f"\n  chargement de l'autoencodeur Windows…")
    ev = charger_evaluateur("windows", racine=os.path.join(_RACINE, "models"))
    print(f"  fenêtre {ev.taille} logs | seuil {ev.seuil:.4f}")

    print(f"\n  évaluation par fenêtre…")
    verdicts = ev.evaluer(logs)
    erreurs = [v["erreur"] for v in verdicts if v.get("erreur") is not None]
    suspectes = sum(1 for v in verdicts if v.get("suspect"))

    print(f"\n{'=' * 70}\n  RÉSULTAT\n{'=' * 70}")
    print(f"    {len(verdicts)} fenêtre(s) évaluée(s)")
    print(f"    signalées suspectes : {suspectes} ({suspectes/len(verdicts):.1%})"
          if verdicts else "    aucune fenêtre")

    if erreurs:
        erreurs.sort()
        print(f"    erreur de reconstruction : min {erreurs[0]:.3f}  "
              f"med {erreurs[len(erreurs)//2]:.3f}  max {erreurs[-1]:.3f}")
        print(f"    seuil du modèle          : {ev.seuil:.3f}")

    print(f"\n  COMPARAISON AVEC LE LAB (référence déjà mesurée)")
    print(f"    Lab  (20 000 logs, début du fichier) : 100.0% suspectes, "
          f"erreur médiane 40.622")
    taux_real = suspectes / len(verdicts) if verdicts else 0.0
    print(f"    Real ({len(verdicts)} fenêtre(s))"
          f"{' '*(20-len(str(len(verdicts))))} : {taux_real:.1%} suspectes"
          + (f", erreur médiane {erreurs[len(erreurs)//2]:.3f}" if erreurs else ""))

    print()
    if taux_real >= 0.95:
        print("  → SATURATION CONFIRMÉE sur un environnement totalement")
        print("    différent. La cause est STRUCTURELLE : le corpus")
        print("    d'entraînement n'est pas représentatif d'un journal")
        print("    Windows réel, quel que soit l'environnement. Un")
        print("    réentraînement sur un échantillonnage large est requis.")
    elif taux_real <= 0.30:
        print("  → PAS DE SATURATION sur Real. L'échec précédent semble")
        print("    donc SPÉCIFIQUE à l'extrait du Lab utilisé (les 100 000")
        print("    premières lignes, denses en attaques). À reconfirmer en")
        print("    retestant le Lab sur un échantillon PLUS LARGE et mieux")
        print("    réparti avant de conclure quoi que ce soit sur le modèle")
        print("    lui-même.")
    else:
        print("  → RÉSULTAT INTERMÉDIAIRE, ni saturation totale ni absence")
        print("    de faux positifs. Nécessite un échantillon plus large")
        print("    pour trancher.")

    # profil des features, pour diagnostiquer une éventuelle divergence
    if logs:
        import numpy as np
        blocs = [logs[i:i + ev.taille] for i in range(0, len(logs), ev.taille)
                 if len(logs[i:i + ev.taille]) >= 10]
        if blocs:
            X = np.array([fenetre_vers_scores(b) for b in blocs])
            print(f"\n  PROFIL MOYEN DES FENÊTRES REAL (8 premières features)")
            for i, n in enumerate(NOMS_SCORES[:8]):
                print(f"    {n:16s} {X[:, i].mean():8.3f}")


if __name__ == "__main__":
    main()
