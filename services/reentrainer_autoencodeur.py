"""
=============================================================================
RÉENTRAÎNEMENT DE L'AUTOENCODEUR WINDOWS — sur real_entrainement.csv
=============================================================================
⚠️ CE QUE CE SCRIPT CORRIGE
    L'autoencodeur original a été entraîné sur une zone étroite du Lab
    (essentiellement registre + accès processus), et sature à 100 % de faux
    positifs sur toute fenêtre au profil différent — mesuré à la fois sur
    une autre zone du Lab et sur Real Environment (voir test_autoencodeur_
    real.py). La cause : des features à variance quasi nulle à
    l'entraînement (r_dll, r_process, r_network) explosent au moindre écart.

    `real_entrainement.csv` porte 2 717 970 événements bénins réels, issus
    de 8 hôtes sur un mois complet d'usage normal — une diversité de profils
    que l'entraînement original n'avait pas.

⚠️ ARCHITECTURE ET PROTOCOLE REPRODUITS À L'IDENTIQUE
    Seules les DONNÉES changent. L'architecture (22→16→8→3, Linear+ReLU),
    la fenêtre (50 logs), le calcul des 22 features et le seuil au 98e
    percentile de l'erreur de reconstruction sont repris du modèle original
    (models/collect_autoencoder_final_config.pkl) — pour que toute
    amélioration mesurée soit imputable aux données, pas à la méthode.

USAGE (dans le conteneur agentic-collect, qui a torch)
    docker cp real_entrainement.csv agentic-collect:/tmp/
    docker cp services/reentrainer_autoencodeur.py agentic-collect://app/services/
    docker exec agentic-collect sh -c \
        "python /app/services/reentrainer_autoencodeur.py --csv /tmp/real_entrainement.csv"
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


def charger_logs_reels_csv(chemin: str, taux_eventid_10: float = 0.10,
                           seed: int = 42):
    """
    Lit real_entrainement.csv et convertit chaque ligne en CanonicalLog.

    ⚠️ SOUS-ÉCHANTILLONNAGE DE L'EVENTID 10 (ProcessAccess)
        Sur Real Environment, 97 % des événements bruts sont du ProcessAccess
        — un tirage aléatoire UNIFORME du corpus préserve mécaniquement ce
        déséquilibre. Résultat mesuré : des fenêtres à 99,6 % ProcessAccess
        en moyenne, un modèle qui n'apprend qu'un seul profil, saturation à
        83 % sur le jeu de test dès qu'une fenêtre s'en écarte un peu (voir
        test_autoencodeur_real.py).

        Le filtrage se fait ICI, sur le FLUX DE LOGS, avant tout fenêtrage —
        pas après coup sur les fenêtres déjà construites. C'est plus fidèle
        à ce que ferait un vrai pipeline de collecte équilibré : réduire le
        volume d'un type d'événement bruyant à la source, pas reconstituer
        l'équilibre a posteriori.

        Les autres catégories (registre, réseau, DLL, fichier, injection,
        accès processus... non-10) sont conservées à 100 % : elles sont déjà
        rares, les réduire aggraverait le problème plutôt que de le résoudre.
    """
    import csv
    import random
    from collect_agent.sysmon_mapper import map_sysmon_event

    rng = random.Random(seed)
    logs = []
    n_lu = n_10_vus = n_10_gardes = 0
    with open(chemin, newline="", encoding="utf-8", errors="ignore") as f:
        for ligne in csv.DictReader(f):
            n_lu += 1
            eid = (ligne.get("event_id") or "").strip()
            if eid == "10":
                n_10_vus += 1
                if rng.random() >= taux_eventid_10:
                    continue     # rejeté : trop de ProcessAccess déjà gardé
                n_10_gardes += 1

            horodatage = (ligne.get("@timestamp") or "").strip()
            if not horodatage:
                continue
            horodatage = horodatage.replace("T", " ").replace("Z", "")
            if "." not in horodatage:
                horodatage += ".000"
            brut = {
                "EventID": eid,
                "UtcTime": horodatage[:23],
                "Computer": (ligne.get("host_name") or "inconnu").strip(),
                "ProcessGuid": (ligne.get("process_guid") or "").strip(),
                "Image": (ligne.get("process_path")
                          or ligne.get("process_name") or "").strip(),
            }
            if not brut["EventID"]:
                continue
            r = map_sysmon_event(brut, replay_mode=True)
            log = getattr(r, "log", None)
            if log is not None:
                logs.append(log)

    print(f"  EventID 10 : {n_10_vus:,} vus, {n_10_gardes:,} conservés "
          f"(taux {taux_eventid_10:.0%})")
    print(f"  {n_lu:,} lignes lues → {len(logs):,} logs retenus après "
          f"rééquilibrage")
    return logs


def construire_matrice(logs: list, taille_fenetre: int = 50,
                       max_part_categorie: float = 0.70):
    """
    Découpe en fenêtres non chevauchantes, calcule les 22 scores.

    ⚠️ REJET DES FENÊTRES DOMINÉES PAR UNE SEULE CATÉGORIE
        Le sous-échantillonnage au niveau du LOG (charger_logs_reels_csv,
        taux_eventid_10) n'a pas suffi : les EventID 10 restants, même
        réduits à 10 % du corpus, se regroupent en RAFALES temporelles sur
        les mêmes hôtes — mesuré, la moyenne de n_procaccess restait à 48,3
        sur 50 après ce premier filtrage. Le déséquilibre se recrée à
        l'intérieur de chaque fenêtre, pas seulement dans le volume global.

        On filtre donc directement au niveau de la FENÊTRE : si une seule
        catégorie dépasse `max_part_categorie` (70% par défaut) des 50 logs,
        la fenêtre est rejetée plutôt que gardée avec un profil biaisé. Coûte
        du volume, mais garantit que ce que le modèle apprend reflète une
        activité mêlée — ce qui est le comportement recherché : détecter un
        écart au normal suppose d'avoir appris un normal réellement varié.
    """
    from collect_agent.window_integrity import fenetre_vers_scores, categorie, _event_id
    from collections import Counter
    import numpy as np

    X = []
    n_rejetees_taille = n_rejetees_diversite = 0
    for i in range(0, len(logs), taille_fenetre):
        bloc = logs[i:i + taille_fenetre]
        if len(bloc) < taille_fenetre:
            n_rejetees_taille += 1
            continue

        cats = Counter(categorie(_event_id(l)) for l in bloc)
        part_max = max(cats.values()) / len(bloc)
        if part_max > max_part_categorie:
            n_rejetees_diversite += 1
            continue

        X.append(fenetre_vers_scores(bloc))

    print(f"  fenêtres rejetées : {n_rejetees_taille} (incomplètes) + "
          f"{n_rejetees_diversite} (dominées à >{max_part_categorie:.0%} "
          f"par une catégorie)")
    return np.array(X, dtype=float)


def entrainer(X, epochs: int = 100, lr: float = 1e-3, seed: int = 42):
    """
    Reproduit l'architecture 22→16→8→3, entraîne sur X normalisé (z-score).

    ⚠️ La normalisation (mean, std) est celle du NOUVEAU corpus — c'est
    elle qui corrige le problème initial (features à variance quasi nulle
    apprises sur un profil trop étroit).
    """
    import torch
    import torch.nn as nn
    import numpy as np

    torch.manual_seed(seed)
    np.random.seed(seed)

    mean = X.mean(axis=0)
    std = X.std(axis=0)
    std[std < 1e-6] = 1e-6      # évite une division par zéro, pas une variance nulle
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
    idx = torch.randperm(len(Xt))
    Xt_train, Xt_val = Xt[idx[n_val:]], Xt[idx[:n_val]]

    print(f"  entraînement : {len(Xt_train)} fenêtres | validation : {len(Xt_val)}")
    for ep in range(epochs):
        modele.train()
        opt.zero_grad()
        out = modele(Xt_train)
        perte = perte_fn(out, Xt_train)
        perte.backward()
        opt.step()
        if (ep + 1) % 20 == 0 or ep == 0:
            modele.eval()
            with torch.no_grad():
                perte_val = perte_fn(modele(Xt_val), Xt_val).item()
            print(f"    epoch {ep+1:3d}/{epochs} — perte train {perte.item():.4f} "
                  f"| val {perte_val:.4f}")

    # erreur de reconstruction sur l'ensemble d'entraînement, pour calibrer
    # le seuil EXACTEMENT comme le modèle original (98e percentile)
    modele.eval()
    with torch.no_grad():
        erreurs = ((modele(Xt) - Xt) ** 2).mean(dim=1).numpy()
    seuil = float(np.percentile(erreurs, 98))

    return modele, mean, std, seuil, erreurs


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--csv", required=True, help="real_entrainement.csv")
    p.add_argument("--epochs", type=int, default=100)
    p.add_argument("--taux-eventid-10", type=float, default=0.30,
                   help="proportion d'EventID 10 (ProcessAccess) conservée "
                        "AVANT fenêtrage. Le vrai rééquilibrage se fait "
                        "maintenant par fenêtre (--max-part-categorie) : ce "
                        "taux sert seulement à limiter le volume total, pas "
                        "à garantir la diversité à lui seul.")
    p.add_argument("--max-part-categorie", type=float, default=0.70,
                   help="rejette les fenêtres où une catégorie dépasse "
                        "cette proportion des 50 logs")
    p.add_argument("--sortie-modele", default="collect_autoencoder_real.pt")
    p.add_argument("--sortie-config", default="collect_autoencoder_real_config.pkl")
    args = p.parse_args()

    print("=" * 70)
    print("  RÉENTRAÎNEMENT — Autoencodeur Windows sur Real Environment")
    print("=" * 70)

    print(f"\n  chargement de {args.csv}…")
    logs = charger_logs_reels_csv(args.csv, taux_eventid_10=args.taux_eventid_10)
    print(f"  {len(logs):,} logs acceptés par le mapper")
    if len(logs) < 50_000:
        print("  ⚠️ Corpus faible pour un réentraînement représentatif.")

    print(f"\n  construction des fenêtres (50 logs, non chevauchantes)…")
    X = construire_matrice(logs, max_part_categorie=args.max_part_categorie)
    print(f"  {X.shape[0]:,} fenêtres, {X.shape[1]} features")

    import numpy as np
    print(f"\n  PROFIL DU NOUVEAU CORPUS D'ENTRAÎNEMENT (comparaison avec l'ancien)")
    from collect_agent.window_integrity import NOMS_SCORES
    for i, n in enumerate(NOMS_SCORES[:8]):
        print(f"    {n:16s} moy {X[:,i].mean():8.3f}  std {X[:,i].std():8.3f}")

    print(f"\n  entraînement ({args.epochs} epochs)…")
    modele, mean, std, seuil, erreurs = entrainer(X, epochs=args.epochs)

    print(f"\n  seuil calibré (98e percentile) : {seuil:.4f}")
    print(f"  erreur : min {erreurs.min():.4f}  med {np.median(erreurs):.4f}  "
          f"max {erreurs.max():.4f}")

    import torch, joblib
    torch.save(modele.state_dict(), args.sortie_modele)
    config = {
        "seuil": seuil, "window_size": 50, "percentile_seuil": 98,
        "mean": mean, "std": std, "score_names": NOMS_SCORES,
        "role": "score d'intégrité (legitimate/suspect) → Decision Agent",
        "source": "Real Environment (COMISET) — 8 hôtes entraînement",
        "n_fenetres_entrainement": int(X.shape[0]),
    }
    joblib.dump(config, args.sortie_config)
    print(f"\n  modèle : {args.sortie_modele}")
    print(f"  config : {args.sortie_config}")
    print(f"\n  → Prochaine étape : mesurer sur real_test.csv (5 hôtes jamais")
    print(f"    vus) pour vérifier que la saturation a disparu.")


if __name__ == "__main__":
    main()
