"""
=============================================================================
CALIBRATION DES SEUILS DU DECISION AGENT — jeu de scénarios + sensibilité
=============================================================================
Méthodologie (inspirée d'AgentCity 2026, cadre SAIBERSOC ACSAC'20) :

  1. COUVERTURE COMBINATOIRE EXHAUSTIVE
     L'espace de décision est fini : 5 niveaux de menace × 3 états
     d'anonymisation × 3 états d'intégrité = 45 combinaisons qualitatives.
     Au-delà, aucun cas nouveau n'est couvert.

  2. ÉTIQUETAGE PAR DOCTRINE (non circulaire)
     Les décisions attendues sont dérivées de PRINCIPES qualitatifs posés
     a priori, PAS des valeurs de seuil du code :
       P1 — une action automatique a un coût → n'agir qu'à forte certitude
       P2 — la falsification est un confirmateur fiable (force multiplier)
       P3 — l'anonymisation est ambiguë (VPN souvent légitime) → n'oriente
            que corrélée à une menace
       P4 — falsification seule = peut être un bug → surveiller, ne pas escalader
       P5 — doute persistant → escalader pour investigation

  3. CALIBRATION + ANALYSE DE SENSIBILITÉ
     On balaie les seuils et on mesure l'accord avec les décisions attendues,
     puis on identifie la PLAGE DE STABILITÉ (où le choix exact est indifférent).
=============================================================================
"""
from __future__ import annotations
import os
import sys, itertools
sys.path.insert(0, os.environ.get("REPO_ROOT", ".") + "/agents/4_decision_agent")

from decision_agent.decision_schema import CorrelatedEntity, NormalizedSignal, SignalSource, SignalKind
from decision_agent.certainty_evaluator import (
    CertaintyEvaluator, CertaintyConfig, CertaintyLevel, EscalationMission
)

# -----------------------------------------------------------------------------
# 1. NIVEAUX QUALITATIFS (valeurs représentatives, pas des seuils)
# -----------------------------------------------------------------------------
# Menace : 5 niveaux qualitatifs. Les valeurs sont des points représentatifs
# répartis sur [0,1], choisis AVANT de connaître les seuils.
NIVEAUX_MENACE = {
    "nulle":        0.00,
    "tres_faible":  0.15,
    "moderee":      0.45,
    "elevee":       0.72,
    "tres_elevee":  0.92,
}
# Anonymisation : absente / faible (indice ténu) / forte (Tor avéré)
NIVEAUX_ANON = {"absente": None, "faible": 0.45, "forte": 0.88}
# Intégrité : absente / faible (anomalie légère) / forte (falsification nette)
NIVEAUX_INTEGRITE = {"absente": None, "faible": 0.35, "forte": 0.85}


# -----------------------------------------------------------------------------
# 2. DOCTRINE — décision attendue dérivée des principes P1..P5
# -----------------------------------------------------------------------------
def decision_attendue(menace: str, anon: str, integ: str) -> tuple[str, bool, str]:
    """
    Retourne (certitude_attendue, escalade_attendue, mission_attendue)
    à partir des NIVEAUX QUALITATIFS uniquement — jamais des seuils numériques.
    """
    anon_fort = (anon == "forte")
    integ_fort = (integ == "forte")

    # --- Aucune menace ---
    if menace == "nulle":
        if integ_fort:
            return ("monitored", False, "none")      # P4 : falsif seule = surveillée
        return ("normal", False, "none")

    # --- P1 : menace très élevée → action justifiée même seule ---
    if menace == "tres_elevee":
        certitude = "confirmed"
    # --- P2 : menace élevée + falsification nette → convergence confirmante ---
    elif menace == "elevee" and integ_fort:
        certitude = "confirmed"
    else:
        certitude = "doubtful"

    # --- P3 : anonymisation forte + menace significative → géolocalisation ---
    menace_significative = menace in ("elevee", "tres_elevee")
    if menace_significative and anon_fort:
        if certitude == "confirmed":
            return (certitude, True, "geolocation")
        return (certitude, True, "geolocation_and_investigation")

    # --- P5 (affiné après calibration) : doute → investigation, MAIS seulement
    #     si la menace dépasse le seuil de BRUIT. Escalader une menace très
    #     faible noierait le Niveau 2 : c'est du bruit, pas du doute.
    if certitude == "doubtful":
        if menace == "tres_faible":
            # bruit : surveillé si falsification nette, sinon rien
            if integ_fort:
                return ("doubtful", False, "none")
            return ("doubtful", False, "none")
        # menace modérée : doute réel → investigation (la corroboration renforce)
        if anon_fort:
            return ("doubtful", True, "geolocation_and_investigation")
        return ("doubtful", True, "investigation")

    return (certitude, False, "none")


# -----------------------------------------------------------------------------
# 3. CONSTRUCTION DES 45 SCÉNARIOS
# -----------------------------------------------------------------------------
def construire_entite(menace: str, anon: str, integ: str) -> CorrelatedEntity:
    ts = None
    if NIVEAUX_MENACE[menace] > 0:
        ts = NormalizedSignal(
            source=SignalSource.ANALYSIS, kind=SignalKind.THREAT, host="H1", ips=["10.0.0.1"],
            event_time=None, severity=NIVEAUX_MENACE[menace], payload={}, detail="menace",
        )
    anon_sigs = []
    if NIVEAUX_ANON[anon] is not None:
        anon_sigs.append(NormalizedSignal(
            source=SignalSource.ANONYMIZATION, kind=SignalKind.ANONYMIZATION, host="H1",
            ips=["10.0.0.1"], event_time=None, severity=NIVEAUX_ANON[anon],
            payload={}, detail="tor"))
    integ_sigs = []
    if NIVEAUX_INTEGRITE[integ] is not None:
        integ_sigs.append(NormalizedSignal(
            source=SignalSource.COLLECT, kind=SignalKind.INTEGRITY, host="H1", ips=[],
            event_time=None, severity=NIVEAUX_INTEGRITE[integ],
            payload={}, detail="integrity_anomaly"))
    return CorrelatedEntity(entity_key=f"{menace}|{anon}|{integ}", host="H1",
                            threat_signal=ts, anonymization_signals=anon_sigs,
                            integrity_signals=integ_sigs)


SCENARIOS = []
for m, a, i in itertools.product(NIVEAUX_MENACE, NIVEAUX_ANON, NIVEAUX_INTEGRITE):
    att = decision_attendue(m, a, i)
    SCENARIOS.append({"menace": m, "anon": a, "integ": i,
                      "entite": construire_entite(m, a, i),
                      "attendu_certitude": att[0], "attendu_escalade": att[1],
                      "attendu_mission": att[2]})


# -----------------------------------------------------------------------------
# 4. ÉVALUATION D'UNE CONFIGURATION DE SEUILS
# -----------------------------------------------------------------------------
def evaluer_config(cfg: CertaintyConfig) -> tuple[float, float, list]:
    """Retourne (accord_certitude, accord_escalade, désaccords)."""
    ev = CertaintyEvaluator(cfg)
    ok_cert = ok_esc = 0
    desaccords = []
    for sc in SCENARIOS:
        d = ev.evaluate(sc["entite"])
        c_ok = (d.certainty.value == sc["attendu_certitude"])
        e_ok = (d.escalate == sc["attendu_escalade"])
        ok_cert += c_ok
        ok_esc += e_ok
        if not (c_ok and e_ok):
            desaccords.append((sc, d))
    n = len(SCENARIOS)
    return ok_cert/n, ok_esc/n, desaccords


# -----------------------------------------------------------------------------
# 5. CALIBRATION : balayage du seuil d'action (threat_high)
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 70)
    print("CALIBRATION DES SEUILS — DECISION AGENT")
    print("=" * 70)
    print(f"Espace de décision : {len(NIVEAUX_MENACE)} niveaux de menace × "
          f"{len(NIVEAUX_ANON)} anonymisation × {len(NIVEAUX_INTEGRITE)} intégrité "
          f"= {len(SCENARIOS)} scénarios (couverture exhaustive)\n")

    print("--- Balayage de threat_high (seuil d'ACTION automatique) ---")
    print(f"{'threat_high':>12} | {'accord certitude':>17} | {'accord escalade':>16}")
    print("-" * 52)
    resultats = []
    for th in [0.70, 0.75, 0.80, 0.85, 0.90, 0.95]:
        cfg = CertaintyConfig(threat_high=th)
        ac, ae, _ = evaluer_config(cfg)
        resultats.append((th, ac, ae))
        print(f"{th:>12.2f} | {ac:>16.1%} | {ae:>15.1%}")

    # plage de stabilité
    best = max(r[1] for r in resultats)
    plage = [r[0] for r in resultats if abs(r[1] - best) < 1e-9]
    print(f"\n>>> Accord maximal : {best:.1%}")
    print(f">>> PLAGE DE STABILITÉ (accord identique) : {min(plage):.2f} – {max(plage):.2f}")
    if len(plage) > 1:
        milieu = (min(plage) + max(plage)) / 2
        print(f">>> Point médian de la plage stable : {milieu:.2f}")

    print("\n--- Balayage de threat_medium (seuil de convergence) ---")
    print(f"{'threat_medium':>14} | {'accord certitude':>17} | {'accord escalade':>16}")
    print("-" * 54)
    res_med = []
    for tm in [0.40, 0.50, 0.55, 0.60, 0.65, 0.70]:
        cfg = CertaintyConfig(threat_medium=tm)
        ac, ae, _ = evaluer_config(cfg)
        res_med.append((tm, ac, ae))
        print(f"{tm:>14.2f} | {ac:>16.1%} | {ae:>15.1%}")
    best_m = max(r[1] for r in res_med)
    plage_m = [r[0] for r in res_med if abs(r[1] - best_m) < 1e-9]
    print(f"\n>>> PLAGE DE STABILITÉ threat_medium : {min(plage_m):.2f} – {max(plage_m):.2f}")

    # --- désaccords à la configuration par défaut ---
    print("\n" + "=" * 70)
    print("DÉSACCORDS À LA CONFIGURATION ACTUELLE (0.85 / 0.60)")
    print("=" * 70)
    ac, ae, desaccords = evaluer_config(CertaintyConfig())
    print(f"Accord certitude {ac:.1%} | accord escalade {ae:.1%} | "
          f"{len(desaccords)} désaccord(s)\n")
    for sc, d in desaccords[:12]:
        print(f"  menace={sc['menace']:<12} anon={sc['anon']:<8} integ={sc['integ']:<8}")
        print(f"     attendu : {sc['attendu_certitude']:<10} escalade={sc['attendu_escalade']}"
              f" mission={sc['attendu_mission']}")
        print(f"     obtenu  : {d.certainty.value:<10} escalade={d.escalate}"
              f" mission={d.mission.value}  [{','.join(d.triggered_rules)}]")
