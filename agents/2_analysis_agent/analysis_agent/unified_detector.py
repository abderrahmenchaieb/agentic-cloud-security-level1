# =============================================================================
# DÉTECTEUR UNIFIÉ (Windows + Cloud) — Analysis Agent
# =============================================================================
# Un SEUL détecteur, une SEULE interface (fit / predict), qui ROUTE chaque
# séquence vers le jeu de features et le modèle adaptés à sa SOURCE :
#   - séquence endpoint (Sysmon)  → features Windows → modèle Windows
#   - séquence cloud (CloudTrail) → features cloud   → modèle cloud
#
# L'unification opère au niveau de l'AGENT et du SCHÉMA CANONIQUE : le reste du
# système ne voit qu'un détecteur, avec une sémantique commune (verdict
# attaque/normal + score, orienté RAPPEL). Chaque modèle interne est entraîné
# sur son monde avec ses VRAIES features (pas de features à zéro).
#
# Défendable en thèse : "Le détecteur unifié route chaque séquence vers le jeu
# de features adapté à sa source (endpoint ou cloud), tous deux structurés selon
# la même logique comportementale MITRE. L'unification opère au niveau de l'agent
# et du schéma canonique, garantissant une interface et une sémantique communes."
# =============================================================================

from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from .sequence_schema import Sequence
from .sequence_features import (extract_sequence_features, extract_matrix,
                                FEATURE_NAMES as WIN_FEATURE_NAMES)


@dataclass
class SequenceVerdict:
    sequence_id: str
    is_attack: bool
    attack_score: float
    top_features: list
    source: str = "endpoint"   # "endpoint" | "cloud" : quelle voie a été empruntée


def _detect_source(seq) -> str:
    """
    Détermine la source d'une séquence : cloud ou endpoint.
    Heuristique robuste : une séquence cloud a des événements dont l'action est
    une API cloud (via extra.cloud_service) et sans process_guid.
    """
    events = list(getattr(seq, "events", []))
    if not events:
        return "endpoint"
    # si un événement porte un service cloud dans extra → cloud
    for e in events:
        extra = getattr(e, "extra", None) or {}
        if extra.get("cloud_service") or extra.get("cloud_provider"):
            return "cloud"
    # sinon, si aucun process_guid nulle part et pas de command_line → probablement cloud
    has_proc = any(getattr(e, "process_guid", None) for e in events)
    if not has_proc:
        # signal faible : on regarde si les process_name ressemblent à des API (CamelCase sans .exe)
        names = [getattr(e, "process_name", "") or "" for e in events]
        if names and all(not n.endswith(".exe") and n[:1].isupper() for n in names if n):
            return "cloud"
    return "endpoint"


class _SubDetector:
    """Un détecteur pour UN monde (Windows ou Cloud). Interne."""

    def __init__(self, feature_fn, matrix_fn, feature_names, recall_threshold,
                 random_state):
        self._feature_fn = feature_fn
        self._matrix_fn = matrix_fn
        self._feature_names = feature_names
        self.recall_threshold = recall_threshold
        self.scaler = StandardScaler()
        self.model = RandomForestClassifier(
            n_estimators=200, max_depth=None, class_weight="balanced",
            random_state=random_state)
        self._fitted = False

    def fit(self, sequences, labels):
        X = np.array(self._matrix_fn(sequences), dtype=float)
        Xs = self.scaler.fit_transform(X)
        self.model.fit(Xs, labels)
        self._fitted = True
        return self

    def predict(self, seq) -> tuple:
        if not self._fitted:
            raise RuntimeError("Sous-détecteur non entraîné.")
        feats = np.array(self._feature_fn(seq), dtype=float).reshape(1, -1)
        Xs = self.scaler.transform(feats)
        score = float(self.model.predict_proba(Xs)[0, 1])
        is_attack = score >= self.recall_threshold
        importances = self.model.feature_importances_
        top_idx = np.argsort(importances)[::-1][:3]
        top_features = [self._feature_names[i] for i in top_idx]
        return is_attack, score, top_features


class UnifiedSequenceDetector:
    """
    Détecteur unifié attaque/normal, orienté RAPPEL. Route selon la source.
    Interface identique à l'ancien SequenceDetector (fit/predict/predict_batch),
    plus des méthodes fit_endpoint / fit_cloud pour entraîner chaque voie.
    """

    def __init__(self, recall_threshold: float = 0.3, random_state: int = 42,
                 aligned_windows_features: bool = False):
        # import tardif des features cloud. On importe le MODULE directement
        # (sans déclencher tout le package cloud_adapter, qui dépend de
        # collect_agent) pour rester découplé.
        import importlib
        try:
            mod = importlib.import_module("cloud_adapter.cloud_sequence_features")
        except Exception:
            # fallback : charger le fichier par chemin si le package n'est pas importable
            import importlib.util, os
            here = os.path.dirname(__file__)
            candidates = [
                os.path.join(here, "..", "..", "..", "cloud_adapter", "cloud_adapter",
                             "cloud_sequence_features.py"),
                os.path.join(here, "cloud_sequence_features.py"),
            ]
            mod = None
            for path in candidates:
                if os.path.exists(path):
                    spec = importlib.util.spec_from_file_location(
                        "cloud_sequence_features", path)
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    break
            if mod is None:
                raise ImportError("Module cloud_sequence_features introuvable")
        extract_cloud_features = mod.extract_cloud_features
        extract_cloud_matrix = mod.extract_cloud_matrix
        CLOUD_FEATURE_NAMES = mod.FEATURE_NAMES

        # Extracteur Windows : deux jeux de features coexistent.
        #  - historique (14 features sémantiques) : suppose des command_line,
        #    conservé par défaut pour ne pas casser le code et les tests existants
        #  - aligné (18 features structurelles) : correspond au modèle réellement
        #    entraîné sur COMISET (où command_line est quasi absent)
        # Le second est REQUIS pour brancher windows_detector.pkl.
        if aligned_windows_features:
            from .windows_features_aligned import (
                extract_windows_features, extract_windows_matrix,
                WINDOWS_FEATURE_NAMES)
            win_fn, win_matrix, win_names = (
                extract_windows_features, extract_windows_matrix,
                WINDOWS_FEATURE_NAMES)
        else:
            win_fn, win_matrix, win_names = (
                extract_sequence_features, extract_matrix, WIN_FEATURE_NAMES)

        self._endpoint = _SubDetector(
            win_fn, win_matrix, win_names, recall_threshold, random_state)
        self._cloud = _SubDetector(
            extract_cloud_features, extract_cloud_matrix, CLOUD_FEATURE_NAMES,
            recall_threshold, random_state)

    # --- entraînement par voie ---
    def fit_endpoint(self, sequences, labels):
        self._endpoint.fit(sequences, labels)
        return self

    def fit_cloud(self, sequences, labels):
        self._cloud.fit(sequences, labels)
        return self

    # --- interface compatible avec l'ancien détecteur ---
    def fit(self, sequences, labels):
        """
        Entraîne en séparant automatiquement les séquences par source.
        Permet un fit unique sur un mélange endpoint+cloud.
        """
        ep_seqs, ep_lbls, cl_seqs, cl_lbls = [], [], [], []
        for s, l in zip(sequences, labels):
            if _detect_source(s) == "cloud":
                cl_seqs.append(s); cl_lbls.append(l)
            else:
                ep_seqs.append(s); ep_lbls.append(l)
        if ep_seqs:
            self._endpoint.fit(ep_seqs, ep_lbls)
        if cl_seqs:
            self._cloud.fit(cl_seqs, cl_lbls)
        return self

    def predict(self, seq) -> SequenceVerdict:
        source = _detect_source(seq)
        sub = self._cloud if source == "cloud" else self._endpoint
        is_attack, score, top = sub.predict(seq)
        return SequenceVerdict(
            sequence_id=getattr(seq, "sequence_id", "?"),
            is_attack=is_attack, attack_score=score,
            top_features=top, source=source)

    def predict_batch(self, sequences) -> list:
        return [self.predict(s) for s in sequences]
