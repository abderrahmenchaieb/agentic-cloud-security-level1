"""
=============================================================================
ENTRAÎNEMENT FINAL — depuis fenetres_entrainement.npz
=============================================================================
Charge la matrice de fenêtres déjà construite (voir
construire_fenetres_entrainement.py — buffer glissant, profil mêlé garanti,
49 007 fenêtres sur 8 hôtes) et entraîne l'autoencodeur.

⚠️ ARCHITECTURE ET PROTOCOLE REPRODUITS À L'IDENTIQUE DE L'ORIGINAL
    22→16→8→3, Linear+ReLU, seuil au 98e percentile de l'erreur de
    reconstruction. Seules les DONNÉES changent — pour que toute
    amélioration mesurée soit imputable au corpus, pas à la méthode.

USAGE (dans le conteneur agentic-collect, qui a torch)
    docker cp fenetres_entrainement.npz agentic-collect:/tmp/
    docker cp services/entrainer_depuis_matrice.py agentic-collect://app/services/
    docker exec agentic-collect sh -c \
        "python /app/services/entrainer_depuis_matrice.py --matrice /tmp/fenetres_entrainement.npz"
=============================================================================
"""
from __future__ import annotations

import argparse
import os
import sys

_ICI = os.path.dirname(os.path.abspath(__file__))
_RACINE = os.path.dirname(_ICI)
for chemin in (_ICI, _RACINE,
               os.path.join(_RACINE, "agents", "1_collect_agent")):
    if chemin not in sys.path:
        sys.path.insert(0, chemin)


def entrainer(X, epochs: int = 150, lr: float = 1e-3, seed: int = 42):
    import torch
    import torch.nn as nn
    import numpy as np

    torch.manual_seed(seed)
    np.random.seed(seed)

    mean = X.mean(axis=0)
    std = X.std(axis=0)
    std[std < 1e-6] = 1e-6
    Xn = (X - mean) / std

    class AE(nn.Module):
        def __init__(self, dim):
            super().__init__()
            self.enc = nn.Sequential(nn.Linear(dim, 16), nn.ReLU(),
                                     nn.Linear(16, 8), nn.ReLU(),
                                     nn.Linear(8, 3))
            self.dec = nn.Sequential(nn.Linear(3, 8), nn.ReLU(),
                                     nn.Linear(8, 16), nn.ReLU(),
                                     nn.Linear(16, dim))
        def forward(self, x):
            return self.dec(self.enc(x))

    modele = AE(X.shape[1])
    opt = torch.optim.Adam(modele.parameters(), lr=lr)
    perte_fn = nn.MSELoss()

    Xt = torch.tensor(Xn, dtype=torch.float32)
    n_val = max(1, int(len(Xt) * 0.1))
    g = torch.Generator().manual_seed(seed)
    idx = torch.randperm(len(Xt), generator=g)
    Xt_train, Xt_val = Xt[idx[n_val:]], Xt[idx[:n_val]]

    print(f"  entraînement : {len(Xt_train):,} fenêtres | "
          f"validation : {len(Xt_val):,}")

    # mini-batchs : 49k exemples ne tiennent pas bien en un seul batch
    taille_batch = 256
    for ep in range(epochs):
        modele.train()
        perm = torch.randperm(len(Xt_train), generator=g)
        perte_epoch = 0.0
        for i in range(0, len(Xt_train), taille_batch):
            batch = Xt_train[perm[i:i + taille_batch]]
            opt.zero_grad()
            out = modele(batch)
            perte = perte_fn(out, batch)
            perte.backward()
            opt.step()
            perte_epoch += perte.item() * len(batch)
        perte_epoch /= len(Xt_train)

        if (ep + 1) % 15 == 0 or ep == 0:
            modele.eval()
            with torch.no_grad():
                perte_val = perte_fn(modele(Xt_val), Xt_val).item()
            print(f"    epoch {ep+1:3d}/{epochs} — perte train {perte_epoch:.4f} "
                  f"| val {perte_val:.4f}")

    modele.eval()
    with torch.no_grad():
        erreurs = ((modele(Xt) - Xt) ** 2).mean(dim=1).numpy()
    seuil = float(np.percentile(erreurs, 98))
    return modele, mean, std, seuil, erreurs


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--matrice", required=True,
                   help="fenetres_entrainement.npz")
    p.add_argument("--epochs", type=int, default=150)
    p.add_argument("--sortie-modele", default="collect_autoencoder_real.pt")
    p.add_argument("--sortie-config", default="collect_autoencoder_real_config.pkl")
    args = p.parse_args()

    print("=" * 70)
    print("  ENTRAÎNEMENT FINAL — depuis matrice pré-calculée")
    print("=" * 70)

    import numpy as np
    d = np.load(args.matrice)
    X = d["X"]
    print(f"  matrice chargée : {X.shape[0]:,} fenêtres, {X.shape[1]} features")
    if X.shape[0] < 5000:
        print("  ⚠️ Corpus faible — réentraîner sur davantage de données")
        print("     serait préférable avant d'en tirer des conclusions.")

    from collect_agent.window_integrity import NOMS_SCORES
    print(f"\n  entraînement ({args.epochs} epochs, mini-batchs de 256)…")
    modele, mean, std, seuil, erreurs = entrainer(X, epochs=args.epochs)

    print(f"\n  seuil calibré (98e percentile) : {seuil:.4f}")
    print(f"  erreur : min {erreurs.min():.4f}  med {np.median(erreurs):.4f}  "
          f"max {erreurs.max():.4f}")
    print(f"\n  distribution complète :")
    for pct in (1, 5,10, 25, 50, 75, 90, 95, 99, 100):
        print(f"    p{pct:3d} : {np.percentile(erreurs, pct):.4f}")

    import torch, joblib
    torch.save(modele.state_dict(), args.sortie_modele)
    config = {
        "seuil": seuil, "window_size": 50, "percentile_seuil": 98,
        "mean": mean, "std": std, "score_names": NOMS_SCORES,
        "role": "score d'intégrité (legitimate/suspect) → Decision Agent",
        "source": "Real Environment (COMISET) — 8 hôtes, fenêtres construites "
                  "par buffer glissant (pas=10, seuil diversité 80%)",
        "n_fenetres_entrainement": int(X.shape[0]),
    }
    joblib.dump(config, args.sortie_config)
    print(f"\n  modèle : {args.sortie_modele}")
    print(f"  config : {args.sortie_config}")
    print(f"\n  → Mesurer sur real_test.csv (5 hôtes jamais vus).")


if __name__ == "__main__":
    main()
