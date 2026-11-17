from __future__ import annotations
from dataclasses import dataclass
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from .sequence_schema import Sequence
from .sequence_features import extract_sequence_features, extract_matrix, FEATURE_NAMES


@dataclass
class SequenceVerdict:
    sequence_id: str
    is_attack: bool
    attack_score: float
    top_features: list[str]


class SequenceDetector:
    """Détecteur binaire attaque/normal, orienté RAPPEL (seuil abaissé)."""

    def __init__(self, recall_threshold: float = 0.3, random_state: int = 42):
        self.recall_threshold = recall_threshold
        self.scaler = StandardScaler()
        self.model = RandomForestClassifier(
            n_estimators=200, max_depth=None, class_weight="balanced",
            random_state=random_state,
        )
        self._fitted = False

    def fit(self, sequences: list[Sequence], labels: list[int]):
        X = np.array(extract_matrix(sequences), dtype=float)
        Xs = self.scaler.fit_transform(X)
        self.model.fit(Xs, labels)
        self._fitted = True
        return self

    def predict(self, seq: Sequence) -> SequenceVerdict:
        if not self._fitted:
            raise RuntimeError("Détecteur non entraîné.")
        feats = np.array(extract_sequence_features(seq), dtype=float).reshape(1, -1)
        Xs = self.scaler.transform(feats)
        score = float(self.model.predict_proba(Xs)[0, 1])
        is_attack = score >= self.recall_threshold
        importances = self.model.feature_importances_
        top_idx = np.argsort(importances)[::-1][:3]
        top_features = [FEATURE_NAMES[i] for i in top_idx]
        return SequenceVerdict(
            sequence_id=seq.sequence_id, is_attack=is_attack,
            attack_score=score, top_features=top_features,
        )

    def predict_batch(self, sequences: list[Sequence]) -> list[SequenceVerdict]:
        return [self.predict(s) for s in sequences]
