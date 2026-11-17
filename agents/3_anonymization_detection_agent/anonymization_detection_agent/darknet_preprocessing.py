# =============================================================================
# PRÉPARATION DE CIC-DARKNET2020
# =============================================================================
# Charge et nettoie le dataset, en traitant ses défauts DOCUMENTÉS :
#   - les colonnes Src IP / Dst IP sont présentes dans le CSV BRUT mais
#     supprimées dans la plupart des versions "preprocessed" → on exige le brut
#   - flux DUPLIQUÉS → dédupliquer (sinon fuite de données train/test)
#   - déséquilibre SÉVÈRE (Tor ultra-minoritaire) → mesurer, rééquilibrer
#   - valeurs infinies/NaN produites par CICFlowMeter → nettoyer
#
# Sortie : une liste de NetworkFlow prêts pour le graphe et le GNN.
#
# NOTE : testé ici sur des données SYNTHÉTIQUES imitant la structure de
# CIC-Darknet2020. Le chargement réel (load_csv) est prêt pour le vrai fichier.
# =============================================================================

from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
import numpy as np

from .flow_schema import NetworkFlow, FlowFeatures, AnonymizationLabel


# Colonnes d'identité attendues dans le CSV BRUT (noms usuels CIC-Darknet2020)
IP_COLUMNS = {
    "src_ip": ["Src IP", "Source IP", "src_ip"],
    "dst_ip": ["Dst IP", "Destination IP", "dst_ip"],
    "src_port": ["Src Port", "Source Port", "src_port"],
    "dst_port": ["Dst Port", "Destination Port", "dst_port"],
    "protocol": ["Protocol", "protocol"],
}

# La colonne de label et le mapping vers nos étiquettes
LABEL_COLUMNS = ["Label", "Label.1", "label"]


def _map_label(raw_label: str) -> AnonymizationLabel:
    """CIC-Darknet2020 : labels à 2 niveaux (Tor/VPN/Non-Tor/NonVPN)."""
    s = str(raw_label).strip().lower()
    if "tor" in s and "non" not in s:
        return AnonymizationLabel.TOR
    if "vpn" in s and "non" not in s:
        return AnonymizationLabel.VPN
    return AnonymizationLabel.NORMAL


@dataclass
class DatasetStats:
    total: int
    n_normal: int
    n_vpn: int
    n_tor: int
    n_duplicates_removed: int
    n_cleaned: int

    def imbalance_ratio(self) -> str:
        parts = []
        for name, n in [("normal", self.n_normal), ("vpn", self.n_vpn), ("tor", self.n_tor)]:
            pct = 100 * n / self.total if self.total else 0
            parts.append(f"{name}={n} ({pct:.1f}%)")
        return " | ".join(parts)


class DarknetPreprocessor:
    """Charge et nettoie CIC-Darknet2020."""

    def __init__(self):
        self.stats: Optional[DatasetStats] = None
        self.feature_names: list[str] = []

    def load_csv(self, path: str) -> "pd.DataFrame":  # noqa: F821
        """
        Charge le CSV BRUT. Vérifie la présence des colonnes IP (indispensables
        pour le graphe). Lève une erreur claire si elles manquent.
        """
        import pandas as pd
        df = pd.read_csv(path, low_memory=False)
        df.columns = [c.strip() for c in df.columns]

        # vérifier la présence des IP (le point critique)
        if not self._find_column(df, IP_COLUMNS["src_ip"]) or \
           not self._find_column(df, IP_COLUMNS["dst_ip"]):
            raise ValueError(
                "Colonnes Src IP / Dst IP absentes. "
                "Utilise le fichier CIC-Darknet2020 BRUT (Darknet.csv), "
                "pas une version 'preprocessed' qui supprime les IP."
            )
        return df

    def _find_column(self, df, candidates: list[str]) -> Optional[str]:
        for c in candidates:
            if c in df.columns:
                return c
        return None

    def prepare(self, df) -> list[NetworkFlow]:
        """Nettoie, déduplique, et convertit en NetworkFlow."""
        import pandas as pd

        n_before = len(df)

        # 1. localiser les colonnes clés
        col_src = self._find_column(df, IP_COLUMNS["src_ip"])
        col_dst = self._find_column(df, IP_COLUMNS["dst_ip"])
        col_sport = self._find_column(df, IP_COLUMNS["src_port"])
        col_dport = self._find_column(df, IP_COLUMNS["dst_port"])
        col_proto = self._find_column(df, IP_COLUMNS["protocol"])
        col_label = self._find_column(df, LABEL_COLUMNS)

        # 2. nettoyer les valeurs infinies/NaN (artefacts CICFlowMeter)
        df = df.replace([np.inf, -np.inf], np.nan)
        # colonnes numériques de features (tout sauf identité/label)
        id_cols = {c for c in [col_src, col_dst, col_sport, col_dport, col_proto, col_label] if c}
        feature_cols = [c for c in df.columns if c not in id_cols]
        numeric_cols = df[feature_cols].select_dtypes(include=[np.number]).columns.tolist()
        df[numeric_cols] = df[numeric_cols].fillna(0.0)
        self.feature_names = numeric_cols

        # 3. dédupliquer (éviter la fuite train/test)
        dedup_cols = [c for c in [col_src, col_dst, col_sport, col_dport, col_proto] if c] + numeric_cols
        df = df.drop_duplicates(subset=dedup_cols)
        n_dups = n_before - len(df)

        # 4. convertir en NetworkFlow
        flows: list[NetworkFlow] = []
        n_normal = n_vpn = n_tor = 0
        for i, row in df.iterrows():
            label = _map_label(row[col_label]) if col_label else AnonymizationLabel.UNKNOWN
            if label == AnonymizationLabel.NORMAL: n_normal += 1
            elif label == AnonymizationLabel.VPN: n_vpn += 1
            elif label == AnonymizationLabel.TOR: n_tor += 1

            feats = FlowFeatures(extra={name: float(row[name]) for name in numeric_cols})
            flows.append(NetworkFlow(
                flow_id=f"flow-{i}",
                src_ip=str(row[col_src]), dst_ip=str(row[col_dst]),
                src_port=int(row[col_sport]) if col_sport and not pd.isna(row[col_sport]) else None,
                dst_port=int(row[col_dport]) if col_dport and not pd.isna(row[col_dport]) else None,
                protocol=str(row[col_proto]) if col_proto else None,
                features=feats, label=label,
            ))

        self.stats = DatasetStats(
            total=len(flows), n_normal=n_normal, n_vpn=n_vpn, n_tor=n_tor,
            n_duplicates_removed=n_dups, n_cleaned=len(numeric_cols),
        )
        return flows

    def balance(self, flows: list[NetworkFlow], strategy: str = "undersample",
                seed: int = 42) -> list[NetworkFlow]:
        """
        Gère le déséquilibre sévère. 'undersample' : réduit la classe majoritaire.
        (En pratique, on peut aussi sur-échantillonner les minoritaires.)
        """
        rng = np.random.default_rng(seed)
        by_label: dict[AnonymizationLabel, list[NetworkFlow]] = {}
        for f in flows:
            by_label.setdefault(f.label, []).append(f)

        if strategy == "undersample":
            n_min = min(len(v) for v in by_label.values())
            balanced = []
            for label, group in by_label.items():
                idx = rng.choice(len(group), size=n_min, replace=False)
                balanced.extend(group[i] for i in idx)
            rng.shuffle(balanced)
            return balanced
        return flows
