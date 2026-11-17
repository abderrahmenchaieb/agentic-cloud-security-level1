"""
=============================================================================
CAMPAGNE EXPÉRIMENTALE — état propre et mesures isolées
=============================================================================
Outillage préalable à toute mesure publiable. Il répond à un problème précis :

⚠️ SANS REMISE À ZÉRO, LES RUNS SE CONTAMINENT
    Le système conserve plusieurs états rémanents entre deux exécutions :

      · le bus garde en mémoire hôtes, attaques, positions et échanges ;
      · Decision garde ses signaux 300 s (fenêtre de corrélation) et la
        liste des entités déjà escaladées ;
      · Analysis garde 50 séquences en cache ;
      · Collect garde ses files de retransmission ;
      · tous les compteurs cumulent depuis le démarrage du conteneur.

    Une entité détectée au run N peut donc être corrélée au run N+1 — on l'a
    observé : une escalade cloud est apparue au milieu d'un run Windows.
    Et « confirmed: 9 » pour 5 entités mélangeait deux exécutions.

    Toute mesure prise dans ces conditions est ininterprétable.

CE QUE FOURNIT CE MODULE

    etat_propre()          remet bus et agents à zéro, vérifie que c'est fait
    mesurer(nom, fn)       exécute une expérience et renvoie ses métriques
                           PROPRES au run, indépendantes des cumuls
    Campagne               enchaîne plusieurs expériences et produit un
                           rapport comparable

USAGE
    from campagne import Campagne
    c = Campagne()
    c.experience("E1 — intégrité fonctionnelle", mon_scenario)
    c.rapport()
=============================================================================
"""
from __future__ import annotations

import json
import time
import urllib.request
from typing import Callable

BUS_URL = "http://127.0.0.1:8000"
AGENTS = {
    "collect": "http://127.0.0.1:9001",
    "analysis": "http://127.0.0.1:9002",
    "anonymization": "http://127.0.0.1:9003",
    "decision": "http://127.0.0.1:9004",
}


def _post(url: str, payload: dict | None = None, timeout: float = 30.0):
    data = json.dumps(payload or {}).encode("utf-8")
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8")
            return json.loads(body) if body else {}
    except Exception:
        return None


def _get(url: str, timeout: float = 20.0):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.load(r)
    except Exception:
        return None


# =============================================================================
def etat_propre(verbeux: bool = True) -> bool:
    """
    Remet le système dans un état vierge et VÉRIFIE que c'est effectif.

    Renvoie False si un agent n'a pas pu être réinitialisé : mieux vaut
    interrompre la campagne que produire des mesures contaminées.
    """
    if verbeux:
        print("  remise à zéro…", end="", flush=True)
    ok = True

    r = _post(f"{BUS_URL}/reset")
    if r is None:
        ok = False
        if verbeux:
            print(" bus INJOIGNABLE", flush=True)

    for nom, url in AGENTS.items():
        if _post(f"{url}/reset") is None:
            ok = False
            if verbeux:
                print(f" {nom} INJOIGNABLE", end="", flush=True)

    # vérification : l'état doit être réellement vide
    time.sleep(1)
    etat = _get(f"{BUS_URL}/state") or {}
    residus = {k: len(etat.get(k) or [])
               for k in ("hosts", "attacks", "positions", "cooperation")}
    if any(residus.values()):
        ok = False
        if verbeux:
            print(f" RÉSIDUS : {residus}", flush=True)
    elif verbeux and ok:
        print(" fait", flush=True)
    return ok


def instantane() -> dict:
    """Compteurs de tous les agents à un instant donné."""
    return {nom: (_get(f"{url}/stats") or {}).get("counters", {})
            for nom, url in AGENTS.items()}


def _delta(avant: dict, apres: dict) -> dict:
    """Différence entre deux instantanés — les métriques PROPRES au run."""
    out = {}
    for agent, compteurs in apres.items():
        av = avant.get(agent, {})
        out[agent] = {k: v - av.get(k, 0) for k, v in compteurs.items()
                      if isinstance(v, (int, float))}
    return out


# =============================================================================
class Campagne:
    """
    Enchaîne des expériences en garantissant l'isolement de chacune.

    Chaque expérience part d'un état vierge, et ses métriques sont calculées
    par DIFFÉRENCE — jamais lues sur les compteurs cumulés du conteneur.
    """

    def __init__(self, attente_stabilisation: float = 900.0):
        self.resultats: list[dict] = []
        self.limite = attente_stabilisation

    def experience(self, nom: str, execution: Callable[[], None],
                   attendre: bool = True) -> dict | None:
        """
        Exécute une expérience isolée.

        `execution` est appelée entre la remise à zéro et la mesure ; elle ne
        doit rien attendre elle-même, la stabilisation est gérée ici.
        """
        print(f"\n{'=' * 70}\n  {nom}\n{'=' * 70}")

        if not etat_propre():
            print("  ÉTAT NON PROPRE — expérience ABANDONNÉE.")
            print("  Les mesures seraient contaminées par le run précédent.")
            return None

        avant = instantane()
        debut = time.time()
        try:
            execution()
        except Exception as e:
            print(f"  échec de l'exécution : {e}")
            return None

        if attendre:
            try:
                from attente import attendre_fin
                attendre_fin(AGENTS["analysis"], AGENTS["decision"],
                             limite=self.limite)
            except Exception:
                time.sleep(30)

        duree = time.time() - debut
        apres = instantane()
        etat = _get(f"{BUS_URL}/state") or {}
        dec = _get(f"{AGENTS['decision']}/stats") or {}

        res = {
            "nom": nom,
            "duree_s": round(duree, 1),
            "metriques_du_run": _delta(avant, apres),
            "etat_final": {
                "hotes": len(etat.get("hosts") or []),
                "attaques": len(etat.get("attacks") or []),
                "positions": len(etat.get("positions") or []),
                "echanges": len(etat.get("cooperation") or []),
            },
            "entites": dec.get("entites", {}),
            "resume_decision": dec.get("resume", {}),
        }
        self.resultats.append(res)
        self._afficher(res)
        return res

    # ------------------------------------------------------------------
    def _afficher(self, r: dict) -> None:
        print(f"\n  durée : {r['duree_s']}s")
        print(f"\n  MÉTRIQUES DU RUN (différences, hors cumuls du conteneur)")
        for agent, m in r["metriques_du_run"].items():
            actifs = {k: v for k, v in m.items() if v}
            if actifs:
                print(f"    {agent:14s} {actifs}")
        print(f"\n  ÉTAT FINAL : {r['etat_final']}")
        rs = r.get("resume_decision") or {}
        if rs:
            print(f"    entités suivies {rs.get('entites_suivies', 0)} | "
                  f"confirmées {rs.get('confirmees', 0)} | "
                  f"investigation {rs.get('en_investigation', 0)} | "
                  f"escaladées {rs.get('escaladees', 0)}")

    def rapport(self) -> None:
        """Synthèse comparable de toutes les expériences."""
        if not self.resultats:
            print("\n  aucune expérience menée.")
            return
        print(f"\n{'=' * 70}\n  SYNTHÈSE DE LA CAMPAGNE ({len(self.resultats)} expériences)"
              f"\n{'=' * 70}")
        print(f"  {'expérience':38s} {'durée':>7s} {'entités':>8s} {'escal.':>7s}")
        print("  " + "-" * 64)
        for r in self.resultats:
            rs = r.get("resume_decision") or {}
            print(f"  {r['nom'][:38]:38s} {r['duree_s']:6.0f}s "
                  f"{rs.get('entites_suivies', 0):8d} {rs.get('escaladees', 0):7d}")

    def exporter(self, chemin: str = "campagne.json") -> None:
        with open(chemin, "w", encoding="utf-8") as f:
            json.dump(self.resultats, f, ensure_ascii=False, indent=2)
        print(f"\n  résultats exportés : {chemin}")


# =============================================================================
def reproductibilite(nom: str, execution: Callable[[], None],
                     n: int = 3) -> dict:
    """
    E0 — le système donne-t-il le MÊME résultat sur des exécutions identiques ?

    ⚠️ Ce contrôle n'est pas une formalité. Le système comporte plusieurs
    facteurs temporels — fenêtre de corrélation, cache de séquences,
    traitement asynchrone, latence variable du LLM — qui peuvent faire
    diverger deux runs pourtant identiques. Une campagne dont les mesures ne
    sont pas reproductibles n'est pas publiable.
    """
    c = Campagne()
    for i in range(n):
        c.experience(f"{nom} — répétition {i + 1}/{n}", execution)

    cles = ("entites_suivies", "confirmees", "en_investigation", "escaladees")
    valeurs = {k: [r.get("resume_decision", {}).get(k, 0) for r in c.resultats]
               for k in cles}
    stable = all(len(set(v)) == 1 for v in valeurs.values())

    print(f"\n{'=' * 70}\n  REPRODUCTIBILITÉ\n{'=' * 70}")
    for k, v in valeurs.items():
        marque = "identique" if len(set(v)) == 1 else "VARIABLE"
        print(f"    {k:20s} {v}  → {marque}")
    print(f"\n  → {'REPRODUCTIBLE' if stable else 'NON REPRODUCTIBLE — '
                                                  'les mesures varient entre runs identiques'}")
    return {"stable": stable, "valeurs": valeurs}
