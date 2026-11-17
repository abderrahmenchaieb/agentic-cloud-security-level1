"""
=============================================================================
ATTENTE DE FIN DE TRAITEMENT
=============================================================================
Détermine quand le pipeline a RÉELLEMENT terminé, plutôt que de deviner à
partir de compteurs figés.

⚠️ POURQUOI CE MODULE EXISTE
    L'ingestion d'Analysis est asynchrone : elle accuse réception puis traite
    en arrière-plan (l'interprétation MITRE via Ollama demande des dizaines de
    secondes sur CPU). Une attente fondée sur la STABILITÉ des compteurs
    conclut donc systématiquement trop tôt : les compteurs ne bougent pas
    pendant qu'Ollama travaille, et le rapport annonce « 0 escalade » alors
    que le système est en plein traitement.

    On interroge donc l'état d'OCCUPATION réel de chaque étage :

        Analysis : `en_cours` — nombre d'analyses non terminées
        Decision : `en_attente` — signaux encore dans la fenêtre de corrélation
                   + un cycle de décision complet après le dernier changement

    Collect et Anonymization traitent en synchrone : leur réponse HTTP vaut
    déjà accusé de fin.
=============================================================================
"""
from __future__ import annotations

import json
import time
import urllib.request


def _get(url: str, timeout: float = 20.0):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.load(r)
    except Exception:
        return None


def attendre_fin(analysis_url: str, decision_url: str,
                 decide_interval: int = 10,
                 limite: float = 900.0,
                 verbeux: bool = True) -> dict:
    """
    Bloque jusqu'à ce que le pipeline ait terminé.

    Renvoie un compte rendu : durée, raison de l'arrêt, et si la limite a été
    atteinte (auquel cas le résultat peut être incomplet — on le dit).
    """
    debut = time.time()
    if verbeux:
        print("  attente de la fin du traitement", end="", flush=True)

    # --- étape 1 : Analysis n'a plus rien en cours -------------------------
    analyses_vues = False
    while time.time() - debut < limite:
        st = _get(f"{analysis_url}/stats")
        if st is None:
            time.sleep(3)
            continue
        en_cours = int(st.get("en_cours", 0) or 0)
        if en_cours > 0:
            analyses_vues = True
            if verbeux:
                print(f"\r  attente — {en_cours} analyse(s) en cours"
                      f" ({time.time()-debut:.0f}s)   ", end="", flush=True)
            time.sleep(3)
            continue
        # rien en cours : laisser une courte marge au cas où un lot vient
        # d'être soumis et n'a pas encore incrémenté le compteur
        time.sleep(3)
        st2 = _get(f"{analysis_url}/stats")
        if int((st2 or {}).get("en_cours", 0) or 0) == 0:
            break

    # --- étape 2 : Decision a eu le temps de décider -----------------------
    # Sa boucle tourne toutes les `decide_interval` secondes ; on attend deux
    # cycles pleins après la fin des analyses pour que la corrélation ait lieu
    # et que les dossiers soient émis.
    # ⚠️ Trois cycles pleins : le dernier signal peut arriver juste après
    #    le début d'un cycle, il faut donc laisser le suivant s'exécuter,
    #    puis un troisième pour que la publication ait lieu. Une marge
    #    trop courte mesurait un système encore en train de décider.
    marge = max(12, decide_interval * 3 + 5)
    if verbeux:
        print(f"\r  analyses terminées — attente d'un cycle de décision"
              f" ({marge}s)          ", end="", flush=True)

    dernier = None
    fin_marge = time.time() + marge
    while time.time() < fin_marge and time.time() - debut < limite:
        time.sleep(3)
        st = _get(f"{decision_url}/stats") or {}
        actuel = tuple(sorted((st.get("counters") or {}).items()))
        if actuel != dernier:
            dernier = actuel
            fin_marge = time.time() + marge   # du nouveau : on prolonge

    duree = time.time() - debut
    atteint_limite = duree >= limite
    if verbeux:
        etat = "délai maximal atteint" if atteint_limite else "terminé"
        print(f"\r  traitement {etat} ({duree:.0f}s)"
              f"{'' if analyses_vues else ' — aucune analyse détectée'}"
              f"                    ")

    return {"duree_s": round(duree, 1),
            "analyses_observees": analyses_vues,
            "limite_atteinte": atteint_limite}
