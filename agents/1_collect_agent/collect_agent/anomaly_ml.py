# =============================================================================
# ML D'ANOMALIE NON-SUPERVISÉ — Collect Agent
# =============================================================================
# Détecte les falsifications INATTENDUES (celles que les règles ne couvrent pas).
#
# Principe : apprendre le "normal" sur un corpus intègre (SANS labels), puis
# signaler les logs qui dévient statistiquement. Isolation Forest : isole les
# points anormaux (peu nombreux, différents) plus vite que les points normaux.
#
# Non-supervisé → cohérent avec le rôle (anomalie de données, pas attaque),
# pas de circularité, pas d'empiètement sur l'Analysis Agent.
# =============================================================================

from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from .canonical_schema import CanonicalLog
from .feature_extraction import extract_matrix, extract_features, FEATURE_NAMES


@dataclass
class AnomalyFinding:
    event_id: str
    anomaly_score: float      # plus élevé = plus anormal
    raw_score: float          # score brut Isolation Forest (décision : <0 = anomalie)
    is_anomaly: bool
    top_features: list[str]   # features qui contribuent le plus à l'anomalie


class AnomalyDetector:
    """
    Détecteur d'anomalie non-supervisé basé sur Isolation Forest.
    S'entraîne sur un corpus INTÈGRE (le "normal"), puis score de nouveaux logs.
    """

    def __init__(self, contamination: float = 0.02, random_state: int = 42):
        # contamination = proportion attendue d'anomalies dans les données de score
        # (faible : on suppose que le normal domine largement)
        self.contamination = contamination
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=random_state,
        )
        self._fitted = False
        self._train_means: Optional[np.ndarray] = None
        self._train_stds: Optional[np.ndarray] = None

    def fit(self, clean_corpus: list[CanonicalLog]):
        """Apprend le 'normal' sur un corpus intègre (sans labels)."""
        X = np.array(extract_matrix(clean_corpus), dtype=float)
        Xs = self.scaler.fit_transform(X)
        self.model.fit(Xs)
        # mémoriser la distribution du normal (pour expliquer les anomalies)
        self._train_means = X.mean(axis=0)
        self._train_stds = X.std(axis=0) + 1e-9
        self._fitted = True
        return self

    def score(self, log: CanonicalLog) -> AnomalyFinding:
        """Score un log : anormal ou non, avec les features responsables."""
        if not self._fitted:
            raise RuntimeError("Le détecteur doit être entraîné (fit) d'abord.")

        feats = np.array(extract_features(log), dtype=float).reshape(1, -1)
        feats_scaled = self.scaler.transform(feats)

        # score_samples : plus c'est BAS (négatif), plus c'est anormal.
        # On garde le score BRUT (il discrimine) et on expose -raw comme
        # "anomaly_score" (plus élevé = plus anormal), SANS sigmoïde qui écrase.
        raw = float(self.model.score_samples(feats_scaled)[0])
        is_anomaly = self.model.predict(feats_scaled)[0] == -1
        anomaly_score = -raw  # inversion simple : plus grand = plus anormal

        # expliquer : quelles features s'écartent le plus du normal (z-score)
        z = np.abs((feats.flatten() - self._train_means) / self._train_stds)
        top_idx = np.argsort(z)[::-1][:3]
        top_features = [FEATURE_NAMES[i] for i in top_idx if z[i] > 1.5]

        return AnomalyFinding(
            event_id=log.event_id,
            anomaly_score=anomaly_score,
            raw_score=raw,
            is_anomaly=bool(is_anomaly),
            top_features=top_features,
        )

    def score_batch(self, logs: list[CanonicalLog]) -> list[AnomalyFinding]:
        return [self.score(l) for l in logs]
