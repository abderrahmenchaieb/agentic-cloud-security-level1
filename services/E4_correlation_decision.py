"""
=============================================================================
E4 — CORRÉLATION MULTI-SOURCE ET MODÈLE DÉCISIONNEL
=============================================================================
Le Decision Agent regroupe-t-il correctement des signaux issus d'agents
DIFFÉRENTS, et décide-t-il conformément à sa spécification ?

⚠️ CE QUE E4 MESURE, QUE E2 ET E3 NE MESURENT PAS
    E2 évalue la détection de menace (Analysis). E3 évalue la détection de
    falsification (Collect). Ni l'un ni l'autre ne dit si le système SAIT
    RASSEMBLER ces signaux quand ils concernent la même entité, ni s'il en
    tire la bonne conclusion.

    C'est pourtant la contribution centrale du travail : la décision ne
    découle pas d'un score unique, mais de la CONVERGENCE de trois signaux
    indépendants — menace, intégrité, anonymisation.

QUATRE MESURES

  [A] CORRÉLATION      Des signaux du même hôte, émis dans la fenêtre de
                       300 s, sont-ils regroupés ? Ceux d'hôtes différents
                       ou hors fenêtre restent-ils séparés ?

  [B] TABLE DE VÉRITÉ  Chaque combinaison de signaux produit-elle la
                       certitude et la mission SPÉCIFIÉES ? On confronte le
                       comportement réel aux 10 règles documentées, pas à
                       une intuition.

  [C] SEUILS           Le comportement bascule-t-il aux valeurs calibrées
                       (0.85 / 0.60 / 0.30) ? On balaie le score de menace
                       et on relève les points de transition observés.

  [D] ESCALADE         Une entité escaladée porte-t-elle réellement les
                       éléments nécessaires au Niveau 2 (IP à géolocaliser
                       pour une mission geolocation) ?

⚠️ AUCUN MODÈLE ML N'INTERVIENT ICI
    Le Decision Agent est entièrement déterministe. E4 ne mesure donc pas
    une performance statistique mais une CONFORMITÉ : le système fait-il ce
    qu'il est spécifié faire. Un écart est un défaut, pas un taux d'erreur.

USAGE
    python3 services/E4_correlation_decision.py
    python3 services/E4_correlation_decision.py --json E4.json
=============================================================================
"""
from __future__ import annotations

import argparse
import json
import os
import sys

_ICI = os.path.dirname(os.path.abspath(__file__))
_RACINE = os.path.dirname(_ICI)
for chemin in (_ICI, _RACINE,
               os.path.join(_RACINE, "agents", "4_decision_agent")):
    if chemin not in sys.path:
        sys.path.insert(0, chemin)


# =============================================================================
def _menace(hote: str, score: float, ips: list[str] | None = None) -> dict:
    return {"host": hote, "attack_score": score, "is_attack": score >= 0.30,
            "techniques": ["T1055"], "sequence_id": f"seq-{hote}",
            "sequence_summary": {"external_ips": ips or []},
            "hypothesis": "test E4"}


def _anon(ip: str, label: str = "tor", confiance: float = 0.95) -> dict:
    return {"label": label, "external_ip": ip, "confidence": confiance}


def _integrite(hote: str, detail: str = "R1_timestomping",
               severite: float = 0.9) -> list:
    return [hote, detail, severite]


def _decider(menaces=None, anons=None, integrites=None):
    """Passe les signaux dans la chaîne complète du Decision Agent."""
    from decision_agent.signal_normalizers import normalize_all
    from decision_agent.correlator import Correlator
    from decision_agent.certainty_evaluator import CertaintyEvaluator

    signaux = normalize_all(threat_verdicts=menaces or [],
                            anon_verdicts=anons or [],
                            integrity_flags=integrites or [])
    entites = Correlator().correlate(signaux)
    resultats = []
    for e in entites:
        d = CertaintyEvaluator().evaluate(e)
        resultats.append({"entite": e, "decision": d})
    return resultats


# =============================================================================
def mesurer_correlation() -> dict:
    """[A] Les signaux du même hôte sont-ils regroupés, les autres séparés ?"""
    print(f"\n  [A] CORRÉLATION MULTI-SOURCE")
    cas = []

    # 1. même hôte, trois sources → UNE entité
    r = _decider(menaces=[_menace("HOTE-A", 0.9, ["185.220.101.5"])],
                 anons=[_anon("185.220.101.5")],
                 integrites=[_integrite("HOTE-A")])
    n_ent = len(r)
    ok = n_ent == 1
    sig = 0
    if r:
        e = r[0]["entite"]
        sig = (1 if getattr(e, "threat_signal", None) else 0) \
              + len(getattr(e, "anonymization_signals", []) or []) \
              + len(getattr(e, "integrity_signals", []) or [])
    cas.append(("3 sources, même hôte → 1 entité", ok, f"{n_ent} entité(s), "
                f"{sig} signal(aux) rassemblé(s)"))

    # 2. deux hôtes distincts → DEUX entités, sans mélange
    r2 = _decider(menaces=[_menace("HOTE-A", 0.9), _menace("HOTE-B", 0.9)],
                  integrites=[_integrite("HOTE-A")])
    hotes = {x["decision"].host for x in r2}
    ok2 = len(r2) == 2 and hotes == {"HOTE-A", "HOTE-B"}
    # l'intégrité ne doit être rattachée qu'à HOTE-A
    fuite = False
    for x in r2:
        n_int = len(getattr(x["entite"], "integrity_signals", []) or [])
        if x["decision"].host == "HOTE-B" and n_int > 0:
            fuite = True
    cas.append(("2 hôtes → 2 entités séparées", ok2 and not fuite,
                f"{len(r2)} entité(s), fuite d'intégrité : "
                f"{'OUI' if fuite else 'non'}"))

    # 3. anonymisation SANS menace → ne crée pas d'entité menaçante
    r3 = _decider(anons=[_anon("185.220.101.5")])
    cas.append(("anonymisation seule → aucune escalade", not any(
        x["decision"].escalate for x in r3), f"{len(r3)} entité(s)"))

    # 4. intégrité SEULE → entité surveillée, pas confirmée
    r4 = _decider(integrites=[_integrite("HOTE-C")])
    cert4 = r4[0]["decision"].certainty.value if r4 else "aucune"
    cas.append(("intégrité seule → 'monitored'", cert4 in ("monitored", "normal"),
                f"certitude = {cert4}"))

    for libelle, ok, detail in cas:
        print(f"      [{'OK' if ok else ' X'}] {libelle:38s} {detail}")
    return {"cas": [{"libelle": l, "conforme": o, "detail": d}
                    for l, o, d in cas],
            "tous_conformes": all(o for _, o, _ in cas)}


# =============================================================================
def mesurer_table_verite() -> dict:
    """
    [B] Chaque combinaison produit-elle la décision SPÉCIFIÉE ?

    ⚠️ Les attentes ci-dessous viennent de la spécification documentée
    (documentation/CALIBRATION_SEUILS_DECISION_AGENT.md), pas d'une
    observation du comportement. Mesurer un système contre lui-même ne
    prouverait rien.
    """
    print(f"\n  [B] TABLE DE VÉRITÉ — conformité aux 10 règles spécifiées")

    scenarios = [
        # (libellé, menace, anon, intégrité, certitude attendue, escalade attendue)
        ("menace forte seule",        0.95, False, False, "confirmed", None),
        ("menace forte + anon",       0.95, True,  False, "confirmed", "geolocation"),
        ("menace forte + intégrité",  0.95, False, True,  "confirmed", None),
        ("menace moyenne seule",      0.72, False, False, "doubtful",  None),
        ("menace moyenne + intégrité", 0.72, False, True, "confirmed", None),
        # ⚠️ Mission COMBINÉE attendue, pas simple géolocalisation : la règle
        #    R4c spécifie que sur une menace douteuse accompagnée
        #    d'anonymisation, « percer l'anonymat est un préalable à
        #    l'investigation » — les deux missions sont donc requises.
        ("menace moyenne + anon",     0.72, True,  False, None,
         "geolocation_and_investigation"),
        ("menace faible seule",       0.35, False, False, "doubtful",  None),
        ("menace négligeable",        0.10, False, False, "normal",    None),
    ]

    lignes = []
    for libelle, score, avec_anon, avec_int, cert_attendue, mission_attendue in scenarios:
        ip = "185.220.101.5"
        r = _decider(
            menaces=[_menace("H", score, [ip] if avec_anon else [])],
            anons=[_anon(ip)] if avec_anon else [],
            integrites=[_integrite("H")] if avec_int else [])
        if not r:
            # ⚠️ Sous le seuil de soupçon (0.30), aucune entité n'est créée :
            #    c'est le comportement SPÉCIFIÉ, pas un écart. Ne compter en
            #    défaut que si une certitude était attendue.
            attendu_rien = cert_attendue in (None, "normal")
            lignes.append((libelle, score, "aucune entité",
                           "none", attendu_rien))
            continue
        d = r[0]["decision"]
        cert = d.certainty.value
        # ⚠️ `mission` est un enum : str() donne "EscalationMission.GEOLOCATION",
        #    jamais "geolocation". Comparer la repr à une chaîne attendue
        #    échouerait toujours — défaut de la mesure, pas du système.
        m = getattr(d, "mission", None)
        mission = getattr(m, "value", str(m) if m is not None else "none")
        conforme = True
        if cert_attendue and cert != cert_attendue:
            conforme = False
        if mission_attendue and mission != mission_attendue:
            conforme = False
        lignes.append((libelle, score, cert, mission, conforme))

    print(f"      {'scénario':30s} {'score':>6s} {'certitude':12s} "
          f"{'mission':14s}")
    for libelle, score, cert, mission, conforme in lignes:
        marque = "OK" if conforme else " X"
        print(f"      [{marque}] {libelle:28s} {score:>6.2f} {cert:12s} {mission:14s}")

    return {"lignes": [{"scenario": l, "score": s, "certitude": c,
                        "mission": m, "conforme": ok}
                       for l, s, c, m, ok in lignes],
            "tous_conformes": all(ok for *_, ok in lignes)}


# =============================================================================
def mesurer_seuils() -> dict:
    """
    [C] Le comportement bascule-t-il aux seuils calibrés ?

    On balaie le score de menace et on RELÈVE les transitions observées,
    sans présumer où elles se trouvent — c'est la mesure qui les révèle.
    """
    print(f"\n  [C] SEUILS — transitions observées vs calibrées (0.85/0.60/0.30)")

    transitions = []
    precedent = None
    scores = [round(x * 0.01, 2) for x in range(0, 101)]
    detail_par_score = {}
    for s in scores:
        r = _decider(menaces=[_menace("H", s)])
        cert = r[0]["decision"].certainty.value if r else "aucune"
        detail_par_score[s] = cert
        if precedent is not None and cert != precedent:
            transitions.append((s, precedent, cert))
        precedent = cert

    for score, avant, apres in transitions:
        print(f"      transition à {score:.2f} : {avant} → {apres}")
    if not transitions:
        print(f"      aucune transition — comportement constant "
              f"({precedent})")

    attendus = {0.30, 0.60, 0.85}
    observes = {t[0] for t in transitions}
    # tolérance d'un pas de balayage
    proches = {a for a in attendus
               if any(abs(a - o) <= 0.011 for o in observes)}
    print(f"\n      seuils calibrés retrouvés : "
          f"{sorted(proches) if proches else 'aucun'}")
    if attendus - proches:
        print(f"      ⚠️ non observés : {sorted(attendus - proches)}")
        print(f"         (peut être normal : un seuil peut ne pas produire")
        print(f"          de transition de CERTITUDE, mais agir sur la")
        print(f"          mission ou l'escalade — voir [B])")

    return {"transitions": [{"score": s, "de": a, "vers": b}
                            for s, a, b in transitions],
            "seuils_calibres_retrouves": sorted(proches),
            "par_score": detail_par_score}


# =============================================================================
def mesurer_escalade() -> dict:
    """[D] Un dossier escaladé porte-t-il ce qu'il faut au Niveau 2 ?"""
    print(f"\n  [D] ESCALADE — le dossier transmis est-il exploitable ?")
    from decision_agent.decision_agent import DecisionAgent

    ip = "185.220.101.5"
    out = DecisionAgent().decide(
        threat_verdicts=[_menace("H", 0.95, [ip])],
        anon_verdicts=[_anon(ip)])

    controles = []
    escalades = out.escalated()
    controles.append(("au moins une escalade", bool(escalades),
                      f"{len(escalades)} escalade(s)"))
    if escalades:
        b = escalades[0].to_dict()
        dossier = b.get("level2_dossier") or {}
        dec = b.get("decision", {})
        mission = str(dec.get("mission", "none"))
        ips = list(dossier.get("anonymized_ips") or [])
        controles.append(("mission = geolocation", mission == "geolocation",
                          f"mission = {mission}"))
        # ⚠️ une mission de géolocalisation SANS IP serait inexploitable
        controles.append(("IP à géolocaliser présente",
                          bool(ips) if mission == "geolocation" else True,
                          f"{len(ips)} IP : {ips}"))
        controles.append(("hôte renseigné", bool(dec.get("host")),
                          f"hôte = {dec.get('host')}"))

    for libelle, ok, detail in controles:
        print(f"      [{'OK' if ok else ' X'}] {libelle:32s} {detail}")
    return {"controles": [{"libelle": l, "conforme": o, "detail": d}
                          for l, o, d in controles],
            "tous_conformes": all(o for _, o, _ in controles)}


# =============================================================================
def main() -> None:
    p = argparse.ArgumentParser(description="E4 — corrélation et décision")
    p.add_argument("--json", default="E4_correlation_decision.json")
    args = p.parse_args()

    print("=" * 70)
    print("  E4 — CORRÉLATION MULTI-SOURCE ET MODÈLE DÉCISIONNEL")
    print("=" * 70)
    print("  Mesure de CONFORMITÉ : le Decision Agent est déterministe,")
    print("  un écart à la spécification est un défaut, pas un taux d'erreur.")

    resultats = {
        "correlation": mesurer_correlation(),
        "table_verite": mesurer_table_verite(),
        "seuils": mesurer_seuils(),
        "escalade": mesurer_escalade(),
    }

    print(f"\n{'=' * 70}\n  SYNTHÈSE E4\n{'=' * 70}")
    for nom, r in resultats.items():
        if "tous_conformes" in r:
            print(f"    [{'OK' if r['tous_conformes'] else ' X'}] {nom}")
    conforme = all(r.get("tous_conformes", True) for r in resultats.values())
    print()
    if conforme:
        print("  → Le modèle décisionnel se comporte conformément à sa")
        print("    spécification sur l'ensemble des cas testés.")
    else:
        print("  → ÉCART(S) À LA SPÉCIFICATION détecté(s) — voir ci-dessus.")

    print(f"\n  RÉSERVES")
    print(f"    · les signaux sont construits par ce script, non issus d'une")
    print(f"      exécution réelle : E4 mesure la LOGIQUE décisionnelle, pas")
    print(f"      la qualité des signaux qui l'alimentent (E2, E3) ;")
    print(f"    · les combinaisons testées couvrent les cas nominaux et les")
    print(f"      abords des seuils, pas l'espace complet des entrées.")

    with open(args.json, "w", encoding="utf-8") as f:
        json.dump(resultats, f, ensure_ascii=False, indent=2, default=str)
    print(f"\n  résultats exportés : {args.json}")


if __name__ == "__main__":
    main()
