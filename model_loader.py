"""
=============================================================================
CHARGEUR DE MODÈLES ENTRAÎNÉS — branchement des artefacts dans le système
=============================================================================
Charge les modèles entraînés hors ligne (Kaggle) et les injecte dans les
composants du système, à la place d'un entraînement au démarrage.

⚠️ POINT CRITIQUE — TRAINING-SERVING SKEW
    Les détecteurs du système appliquent un StandardScaler avant `predict`.
    Or les modèles entraînés sur Kaggle sont des RandomForestClassifier NUS,
    ajustés sur des features BRUTES (aucun scaler exporté).

    Appliquer un scaler à l'inférence alors que le modèle a été entraîné sans
    produirait des prédictions FAUSSES SILENCIEUSEMENT. Ce chargeur installe
    donc un scaler IDENTITÉ quand le modèle n'en a pas.

    Justification de fond : les modèles à arbres (RandomForest, IsolationForest)
    sont insensibles aux échelles — le scaler était inutile, et nuisible ici.

    Chaque chargement vérifie en outre que le nombre de features du modèle
    correspond à celui attendu par le composant, et échoue explicitement sinon.
=============================================================================
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import numpy as np


class _IdentityScaler:
    """Scaler neutre : le modèle a été entraîné sur features brutes."""
    def fit(self, X, y=None): return self
    def transform(self, X): return np.asarray(X, dtype=float)
    def fit_transform(self, X, y=None): return self.transform(X)
    def inverse_transform(self, X): return np.asarray(X, dtype=float)


@dataclass
class LoadedModel:
    """Modèle chargé avec ses métadonnées."""
    model: object
    config: dict
    n_features: int
    path: str
    # ⚠️ Scaler ajusté, présent UNIQUEMENT pour les modèles entraînés sur
    #    features normalisées (format {model, scaler}). None pour les modèles
    #    d'origine, entraînés sur features brutes.
    scaler: object = None

    @property
    def feature_names(self) -> list[str]:
        return self.config.get("feature_names", [])


def load_sklearn_model(model_path: str, config_path: str,
                       expected_features: int | None = None) -> LoadedModel:
    """
    Charge un modèle scikit-learn (RandomForest, IsolationForest) + sa config.
    Vérifie la cohérence du nombre de features.
    """
    import joblib
    charge = joblib.load(model_path)
    # ⚠️ Deux formats acceptés : l'objet modèle seul (entraîné sur features
    #    brutes) ou un dict {model, scaler} (entraîné sur features
    #    normalisées, le scaler ajusté DOIT accompagner le modèle).
    if isinstance(charge, dict) and "model" in charge:
        model, scaler = charge["model"], charge.get("scaler")
    else:
        model, scaler = charge, None
    config = joblib.load(config_path) if Path(config_path).exists() else {}

    n_feat = getattr(model, "n_features_in_", None)
    if n_feat is None:
        n_feat = len(config.get("feature_names", []))
    if expected_features is not None and n_feat != expected_features:
        raise ValueError(
            f"Incohérence de features pour {model_path} : le modèle en attend "
            f"{n_feat}, le composant en fournit {expected_features}. "
            f"Brancher ce modèle produirait des prédictions fausses."
        )
    return LoadedModel(model=model, config=config, n_features=n_feat,
                       path=model_path, scaler=scaler)


def inject_into_subdetector(subdetector, loaded: LoadedModel) -> None:
    """
    Injecte un modèle entraîné dans un _SubDetector du détecteur unifié.
    Installe un scaler IDENTITÉ (le modèle a été entraîné sans normalisation).
    """
    expected = len(getattr(subdetector, "_feature_names", []) or [])
    if expected and loaded.n_features != expected:
        raise ValueError(
            f"Le modèle attend {loaded.n_features} features, le sous-détecteur "
            f"en produit {expected}."
        )
    subdetector.model = loaded.model
    # ⚠️ SCALER — deux cas, à ne pas confondre.
    #    Le modèle d'ORIGINE a été entraîné sur features BRUTES : un scaler
    #    neutre est alors correct, et installer un StandardScaler non ajusté
    #    provoquerait un training-serving skew.
    #    Un modèle RÉENTRAÎNÉ via `SubDetector.fit()`, lui, a été entraîné sur
    #    features NORMALISÉES (`self.scaler.fit_transform(X)`) : il doit
    #    récupérer SON scaler ajusté, sinon il reçoit des features brutes
    #    qu'il ne reconnaît pas — symptôme mesuré : scores écrasés entre 0,11
    #    et 0,35, rappel effondré à 0,018.
    #    Le format de sauvegarde distingue les deux : un dict {model, scaler}
    #    signale un modèle normalisé.
    scaler_sauvegarde = getattr(loaded, "scaler", None)
    subdetector.scaler = scaler_sauvegarde if scaler_sauvegarde is not None \
        else _IdentityScaler()
    subdetector._fitted = True
    if "threshold" in loaded.config:
        subdetector.recall_threshold = float(loaded.config["threshold"])


# ---------------------------------------------------------------------------
# Autoencoders du Collect Agent
# ---------------------------------------------------------------------------
def build_autoencoder(state_dict: dict, input_dim: int):
    """
    Reconstruit l'architecture de l'autoencoder à partir du state_dict.
    Les deux voies ont des architectures différentes :
        Windows : 22 → 16 → 8 → 3   (3 couches)
        Cloud   : 13 → 24 → 12 → 6 → 3 (4 couches, plus profond)
    On les déduit des dimensions des tenseurs plutôt que de les coder en dur.
    """
    import torch
    import torch.nn as nn

    enc_w = [(k, v) for k, v in state_dict.items()
             if k.startswith("enc.") and k.endswith(".weight")]
    dec_w = [(k, v) for k, v in state_dict.items()
             if k.startswith("dec.") and k.endswith(".weight")]
    enc_w.sort(key=lambda kv: int(kv[0].split(".")[1]))
    dec_w.sort(key=lambda kv: int(kv[0].split(".")[1]))

    enc_dims = [enc_w[0][1].shape[1]] + [w.shape[0] for _, w in enc_w]
    dec_dims = [dec_w[0][1].shape[1]] + [w.shape[0] for _, w in dec_w]
    if enc_dims[0] != input_dim:
        raise ValueError(f"L'autoencoder attend {enc_dims[0]} features, "
                         f"{input_dim} fournies.")

    def _stack(dims):
        layers = []
        for i in range(len(dims) - 1):
            layers.append(nn.Linear(dims[i], dims[i+1]))
            if i < len(dims) - 2:
                layers.append(nn.ReLU())
        return nn.Sequential(*layers)

    class AE(nn.Module):
        def __init__(self):
            super().__init__()
            self.enc = _stack(enc_dims)
            self.dec = _stack(dec_dims)
        def forward(self, x):
            return self.dec(self.enc(x))

    model = AE()
    model.load_state_dict(state_dict)
    model.eval()
    return model


class CollectAutoencoder:
    """
    Autoencoder d'intégrité prêt à l'emploi : applique la MÊME normalisation
    qu'à l'entraînement (log sur certaines features pour la voie cloud), puis
    calcule l'erreur de reconstruction.
    """
    def __init__(self, model, config: dict):
        self.model = model
        self.mean = np.asarray(config["mean"], dtype=float)
        self.std = np.asarray(config["std"], dtype=float)
        self.std[self.std == 0] = 1.0
        self.seuil = float(config["seuil"])
        self.score_names = list(config.get("score_names", []))
        self.log_features = list(config.get("log_features", []))
        self.window_size = int(config.get("window_size", 0))
        self._idx = {n: i for i, n in enumerate(self.score_names)}

    def _normalize(self, X):
        X = np.asarray(X, dtype=float)
        if X.ndim == 1:
            X = X.reshape(1, -1)
        Xl = X.copy()
        # normalisation logarithmique — IDENTIQUE à l'entraînement (voie cloud)
        for fn in self.log_features:
            i = self._idx.get(fn)
            if i is not None:
                Xl[:, i] = np.log1p(np.abs(Xl[:, i]))
        return np.nan_to_num((Xl - self.mean) / self.std, nan=0.0)

    def reconstruction_error(self, X) -> np.ndarray:
        import torch
        Xn = self._normalize(X)
        with torch.no_grad():
            t = torch.tensor(Xn, dtype=torch.float32)
            return ((self.model(t) - t) ** 2).mean(1).numpy()

    def is_suspect(self, X) -> np.ndarray:
        return self.reconstruction_error(X) > self.seuil


def load_collect_autoencoder(model_path: str, config_path: str) -> CollectAutoencoder:
    """Charge un autoencoder d'intégrité (Windows ou cloud) prêt à l'emploi."""
    import torch, joblib
    config = joblib.load(config_path)
    state_dict = torch.load(model_path, map_location="cpu", weights_only=True)
    n_feat = len(config["mean"])
    model = build_autoencoder(state_dict, n_feat)
    return CollectAutoencoder(model, config)


# ---------------------------------------------------------------------------
# E-GraphSAGE — agent d'anonymisation (étage 2, le décideur)
# ---------------------------------------------------------------------------
@dataclass
class EGraphSageBundle:
    """
    E-GraphSAGE chargé : poids, scaler et configuration.

    ⚠️ CONTRAINTE PARTICULIÈRE — ce modèle est un GNN, pas un classifieur
    tabulaire. Son inférence exige un GRAPHE construit au préalable :
        nœuds  = adresses IP
        arêtes = flux réseau, portant 76 features
    Architecture (déduite du state_dict) :
        2 couches GraphSAGE : msg 140→64 (= 64 nœud + 76 arête), upd 128→64
        classifieur d'arêtes : 204→64→3  (= 64 source + 64 dest + 76 arête)
    Classes : 0 = normal, 1 = VPN, 2 = Tor (pondération Tor ×8 à l'entraînement).

    Contrairement aux RandomForest du système, ce modèle A ÉTÉ entraîné AVEC
    normalisation : le scaler DOIT être appliqué aux 76 features d'arête avant
    l'inférence, sinon les prédictions seront fausses.
    """
    state_dict: dict
    scaler: object
    config: dict

    @property
    def edge_dim(self) -> int:
        return int(self.config.get("edge_dim", 76))

    @property
    def hidden_dim(self) -> int:
        return int(self.config.get("hidden_dim", 64))

    @property
    def class_mapping(self) -> dict:
        return self.config.get("class_mapping", {"0": "normal", "1": "VPN", "2": "Tor"})

    def scale(self, edge_features):
        """Applique la normalisation utilisée à l'entraînement (obligatoire)."""
        X = np.asarray(edge_features, dtype=float)
        if X.ndim == 1:
            X = X.reshape(1, -1)
        if X.shape[1] != self.edge_dim:
            raise ValueError(f"E-GraphSAGE attend {self.edge_dim} features "
                             f"d'arête, {X.shape[1]} fournies.")
        return self.scaler.transform(X)


def load_egraphsage(model_path: str, scaler_path: str,
                    config_path: str) -> EGraphSageBundle:
    """
    Charge E-GraphSAGE (poids + scaler + config).

    Note : les poids sont retournés en `state_dict`. La reconstruction du
    module PyTorch dépend de l'implémentation du GNN (couches de passage de
    messages), qui vit dans l'agent d'anonymisation — ce chargeur reste
    volontairement agnostique.
    """
    import torch, joblib
    return EGraphSageBundle(
        state_dict=torch.load(model_path, map_location="cpu", weights_only=True),
        scaler=joblib.load(scaler_path),
        config=joblib.load(config_path),
    )
