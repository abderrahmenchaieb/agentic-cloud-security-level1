"""
=============================================================================
SCORE D'INTÉGRITÉ — conversion de l'erreur de reconstruction en sévérité
=============================================================================
Pont entre le Collect Agent (autoencoder) et le Decision Agent.

PROBLÈME
    L'autoencoder produit une ERREUR DE RECONSTRUCTION, non bornée et sans
    signification intrinsèque. Le Decision Agent attend une SÉVÉRITÉ dans [0,1]
    comparable au seuil `integrity_min`.

SOLUTION — calibration de probabilité (Platt scaling)
    On ajuste une régression logistique  err → P(falsifié)  sur les données
    d'évaluation du Collect (erreurs sur fenêtres normales étiquetées 0,
    erreurs sur fenêtres falsifiées étiquetées 1).

    La sévérité transmise devient une PROBABILITÉ CALIBRÉE, ce qui rend le
    seuil du Decision Agent directement interprétable :
        integrity_min = 0.6  ⟺  « ne tenir compte du signal que si la
                                  probabilité de falsification dépasse 60 % »

    Référence : Platt (1999), probability calibration ; « calibrated
    probability thresholding » est l'approche standard pour le seuillage
    sensible aux coûts en SOC (survey arXiv 2605.08316, 2026).

HONNÊTETÉ DE NOMMAGE
    L'autoencoder détecte l'INHABITUEL, pas la falsification prouvée. Le
    signal est donc nommé `integrity_anomaly` et non `tampered` : il remonte
    au Decision Agent comme CONTEXTE, jamais comme preuve.
=============================================================================
"""
from __future__ import annotations
from dataclasses import dataclass
import math


@dataclass
class IntegrityCalibration:
    """
    Paramètres de la calibration Platt :  P(falsifié) = sigmoid(a * err + b)

    Les valeurs par défaut sont dérivées de la calibration du Collect
    (seuil au 98e percentile de l'erreur normale). Elles DOIVENT être
    réajustées sur les erreurs réelles via `fit_calibration()` — voir
    `calibrer_integrite.py`.
    """
    a: float = 1.0          # pente
    b: float = 0.0          # biais
    err_threshold: float = 1.0   # seuil de détection du Collect (percentile 98)
    world: str = "windows"       # "windows" ou "cloud" (calibrations distinctes)

    def probability(self, reconstruction_error: float) -> float:
        """Erreur de reconstruction → probabilité calibrée de falsification."""
        z = self.a * float(reconstruction_error) + self.b
        # sigmoïde numériquement stable
        if z >= 0:
            return 1.0 / (1.0 + math.exp(-z))
        e = math.exp(z)
        return e / (1.0 + e)


def fit_calibration(errors_normal: list[float],
                    errors_tampered: list[float],
                    err_threshold: float,
                    world: str = "windows") -> IntegrityCalibration:
    """
    Ajuste la calibration Platt par régression logistique sur les erreurs
    de reconstruction observées.

    errors_normal   : erreurs sur les fenêtres normales   (label 0)
    errors_tampered : erreurs sur les fenêtres falsifiées (label 1)
    err_threshold   : seuil de détection retenu par le Collect
    """
    try:
        import numpy as np
        from sklearn.linear_model import LogisticRegression
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("numpy et scikit-learn requis pour la calibration") from exc

    X = np.array(list(errors_normal) + list(errors_tampered), dtype=float).reshape(-1, 1)
    y = np.array([0] * len(errors_normal) + [1] * len(errors_tampered), dtype=int)
    lr = LogisticRegression(max_iter=1000)
    lr.fit(X, y)
    return IntegrityCalibration(
        a=float(lr.coef_[0][0]), b=float(lr.intercept_[0]),
        err_threshold=float(err_threshold), world=world,
    )


# -----------------------------------------------------------------------------
# Production du signal d'intégrité destiné au Decision Agent
# -----------------------------------------------------------------------------
@dataclass
class IntegrityScore:
    """Score d'intégrité d'une fenêtre, prêt pour le Decision Agent."""
    host: str
    reconstruction_error: float
    severity: float               # probabilité calibrée de falsification [0,1]
    label: str                    # "legitimate" | "suspect"
    detail: str                   # description honnête, non affirmative

    def to_integrity_flag(self) -> tuple[str, str, float]:
        """Tuple (host, detail, severity) consommable par `normalize_all`."""
        return (self.host, self.detail, self.severity)


def score_window(host: str, reconstruction_error: float,
                 calib: IntegrityCalibration) -> IntegrityScore:
    """
    Convertit une fenêtre analysée par l'autoencoder en score d'intégrité.

    Une fenêtre sous le seuil de détection du Collect est `legitimate` : elle
    ne produit AUCUN signal en aval (évite de noyer le Decision Agent).
    """
    p = calib.probability(reconstruction_error)
    suspect = reconstruction_error > calib.err_threshold
    label = "suspect" if suspect else "legitimate"
    detail = (f"integrity_anomaly ({calib.world}, p={p:.2f})"
              if suspect else "integrity_ok")
    return IntegrityScore(host=host, reconstruction_error=float(reconstruction_error),
                          severity=p, label=label, detail=detail)


def windows_to_integrity_flags(scored: list[IntegrityScore]) -> list[tuple[str, str, float]]:
    """
    Ne conserve que les fenêtres `suspect` et les convertit en integrity_flags.
    Les fenêtres légitimes ne génèrent pas de signal (silence = intégrité OK).
    """
    return [s.to_integrity_flag() for s in scored if s.label == "suspect"]
