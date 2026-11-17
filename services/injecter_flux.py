"""
=============================================================================
INJECTEUR DE FLUX RÉSEAU — activation des deux GNN
=============================================================================
Alimente l'agent Anonymization en flux porteurs des 76 features attendues par
E-GraphSAGE, ce que la voie Sysmon ne peut pas faire (un EventID 3 ne contient
aucune statistique de flux).

DEUX SOURCES POSSIBLES

  1. LE VRAI DATASET — `--csv chemin/vers/Darknet.csv`
     Le fichier BRUT de CIC-Darknet2020, celui qui conserve les Src IP / Dst IP.
     Les versions « preprocessed » de Kaggle les suppriment : sans adresses, le
     graphe ne peut pas être construit.

  2. DISTRIBUTIONS RÉELLES — par défaut, sans CSV
     Les flux sont générés à partir des moyennes et écarts-types RÉELS du
     dataset, lus dans `egraphsage_scaler.pkl` — statistiques apprises sur les
     141 530 flux d'entraînement. Les valeurs sont donc dans le même domaine
     que celles vues par le modèle, et non inventées.

⚠️ CE QUE CE TEST DÉMONTRE, ET CE QU'IL NE DÉMONTRE PAS
     Il démontre que les deux GNN se chargent, construisent leur graphe,
     s'exécutent et produisent des verdicts dans le système réel.

     Il ne réévalue PAS leurs performances. Les chiffres de référence
     (E-GraphSAGE Tor recall 0.906, Anomal-E 0.892) ont été mesurés sur le
     dataset complet avec sa vérité terrain — pas sur des flux régénérés.

USAGE
    python3 injecter_flux.py                    distributions réelles
    python3 injecter_flux.py --csv Darknet.csv  vrai dataset
    python3 injecter_flux.py --n 60             nombre de flux
=============================================================================
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request

ANON_URL = os.environ.get("ANON_URL", "http://127.0.0.1:9003")
_ICI = os.path.dirname(os.path.abspath(__file__))
CONFIG = os.path.join(_ICI, "..", "models", "egraphsage_config.pkl")
SCALER = os.path.join(_ICI, "..", "models", "egraphsage_scaler.pkl")

# IP de sortie Tor réelles (plages publiques bien connues) et VPN
IPS_TOR = ["185.220.101.5", "185.220.101.7", "185.220.102.8", "23.129.64.130"]
IPS_VPN = ["51.15.43.21", "45.83.91.14", "51.158.22.7"]
IPS_NORMALES = ["8.8.8.8", "1.1.1.1", "142.250.75.206", "13.107.42.14"]


def post(url: str, payload: dict, timeout: float = 90.0):
    data = json.dumps(payload, default=str).encode("utf-8")
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8")
            return json.loads(body) if body else {}
    except Exception as e:
        print(f"  [!] {url} : {e}")
        return None


def charger_reference():
    """Colonnes attendues + statistiques réelles du dataset d'entraînement."""
    import joblib
    cfg = joblib.load(CONFIG)
    scaler = joblib.load(SCALER)
    return list(cfg["feature_cols"]), scaler.mean_, scaler.scale_


# -----------------------------------------------------------------------------
# Source 1 — le vrai dataset
# -----------------------------------------------------------------------------
def flux_depuis_csv(chemin: str, colonnes: list[str], n: int) -> list[dict]:
    """
    Lit le CSV brut de CIC-Darknet2020 et en extrait des flux réels.
    Échantillonne en privilégiant la diversité des étiquettes.

    ⚠️ DEUX COLONNES « Label »
        Le fichier brut se termine par « …,Label,Label ». La PREMIÈRE porte la
        catégorie de trafic (Tor / VPN / Non-Tor / NonVPN), la SECONDE le type
        d'application (Chat, Email, Streaming…).

        `csv.DictReader` ne conserve que la dernière colonne d'un nom dupliqué :
        lire « Label » par nom renvoie donc l'application, jamais Tor ni VPN —
        tous les flux ressortent « normal ». On lit par POSITION.

    ⚠️ DATASET TRIÉ PAR CLASSE
        Les flux Tor et VPN sont regroupés plus loin dans le fichier. Un
        échantillonnage sur les premières lignes ne verrait que du normal :
        on parcourt donc tout le fichier jusqu'à remplir chaque quota.
    """
    import csv
    flux, vus = [], {"tor": 0, "vpn": 0, "normal": 0}
    quota = max(1, n // 3)

    def cle(nom): return "".join(c for c in nom.lower() if c.isalnum())

    with open(chemin, newline="", encoding="utf-8", errors="ignore") as fh:
        lecteur = csv.reader(fh)
        entetes = next(lecteur, [])
        pos = {}
        for i, h in enumerate(entetes):
            k = cle(h)
            if k not in pos:            # garder la PREMIÈRE occurrence
                pos[k] = i

        idx_feat = {c: pos[cle(c)] for c in colonnes if cle(c) in pos}
        if len(idx_feat) < len(colonnes) * 0.8:
            print(f"  [!] seulement {len(idx_feat)}/{len(colonnes)} colonnes "
                  f"reconnues — CSV « preprocessed » plutôt que brut ?")

        i_src = pos.get("srcip")
        i_dst = pos.get("dstip")
        i_lab = pos.get("label")        # la PREMIÈRE colonne Label

        for i, ligne in enumerate(lecteur):
            if not ligne or i_lab is None or i_lab >= len(ligne):
                continue
            etiquette = str(ligne[i_lab]).lower()
            # « Non-Tor » et « NonVPN » désignent du trafic normal : tester
            # d'abord la négation, sinon « non-tor » serait classé « tor ».
            if "non" in etiquette:
                categorie = "normal"
            elif "tor" in etiquette:
                categorie = "tor"
            elif "vpn" in etiquette:
                categorie = "vpn"
            else:
                categorie = "normal"

            if vus[categorie] >= quota:
                if all(v >= quota for v in vus.values()):
                    break
                continue
            vus[categorie] += 1

            feats = {}
            for c, j in idx_feat.items():
                try:
                    v = float(ligne[j]) if j < len(ligne) and ligne[j] else 0.0
                    feats[c] = 0.0 if v != v or abs(v) == float("inf") else v
                except (TypeError, ValueError):
                    feats[c] = 0.0

            flux.append({
                "flow_id": f"csv-{i}",
                "src_ip": (ligne[i_src] if i_src is not None and i_src < len(ligne)
                           else "") or "10.0.0.5",
                "dst_ip": (ligne[i_dst] if i_dst is not None and i_dst < len(ligne)
                           else "") or "0.0.0.0",
                "features": feats,
                "_attendu": categorie,
            })

    print(f"  lu depuis le CSV : {vus['tor']} tor, {vus['vpn']} vpn, "
          f"{vus['normal']} normal")
    return flux


# -----------------------------------------------------------------------------
# Source 2 — distributions réelles du dataset
# -----------------------------------------------------------------------------
def flux_depuis_distributions(colonnes: list[str], moyennes, ecarts,
                              n: int) -> list[dict]:
    """
    Génère des flux dans le domaine de valeurs RÉEL du dataset.

    Les trois profils se distinguent par la manière dont ils s'écartent de la
    moyenne — le trafic Tor a des caractéristiques temporelles marquées (trois
    relais successifs allongent les intervalles), le VPN reste plus proche du
    normal, ce qui explique d'ailleurs qu'il soit plus difficile à détecter.
    """
    import numpy as np
    rng = np.random.default_rng(42)
    flux = []
    par_profil = max(1, n // 3)

    # colonnes temporelles : c'est là que Tor se distingue le plus
    idx_temps = [i for i, c in enumerate(colonnes)
                 if any(m in c.lower() for m in ("duration", "iat", "idle", "active"))]

    profils = [
        ("normal", IPS_NORMALES, 1.0, 0.0),
        ("vpn", IPS_VPN, 1.3, 0.5),      # légèrement décalé
        ("tor", IPS_TOR, 2.2, 1.8),      # nettement décalé sur le temporel
    ]

    for categorie, ips, facteur, decalage_temps in profils:
        for k in range(par_profil):
            # tirage dans la distribution apprise, puis décalage selon le profil
            valeurs = moyennes + rng.normal(0, 0.6, len(moyennes)) * ecarts
            valeurs = np.abs(valeurs) * facteur
            for i in idx_temps:
                valeurs[i] *= (1.0 + decalage_temps)
            feats = {c: float(v) for c, v in zip(colonnes, valeurs)}
            flux.append({
                "flow_id": f"gen-{categorie}-{k}",
                "src_ip": "10.0.0.5",
                "dst_ip": ips[k % len(ips)],
                "dst_port": 9001 if categorie == "tor" else 443,
                "protocol": "TCP",
                "features": feats,
                "_attendu": categorie,
            })

    print(f"  généré depuis les distributions réelles : {len(flux)} flux "
          f"({par_profil} par profil)")
    return flux


# -----------------------------------------------------------------------------
def verifier_agent() -> bool:
    try:
        with urllib.request.urlopen(f"{ANON_URL}/health", timeout=5) as r:
            etat = json.load(r)
        print(f"  agent : E-GraphSAGE={etat.get('egraphsage')} "
              f"Anomal-E={etat.get('anomale')}")
        if not etat.get("egraphsage"):
            print("\n  ⚠️ E-GraphSAGE est DÉSACTIVÉ.")
            print("     Le service le désactive quand la source ne fournit pas")
            print("     les 76 features. Ce script les fournit : l'agent devrait")
            print("     les accepter — vérifier son journal de démarrage.")
        return True
    except Exception as e:
        print(f"  agent injoignable ({ANON_URL}) : {e}")
        return False


def main() -> None:
    p = argparse.ArgumentParser(description="Injecteur de flux réseau (GNN)")
    p.add_argument("--csv", help="CSV BRUT de CIC-Darknet2020 (avec les IP)")
    p.add_argument("--n", type=int, default=60, help="nombre de flux")
    args = p.parse_args()

    print("=" * 66)
    print("  INJECTION DE FLUX RÉSEAU — activation des GNN")
    print("=" * 66)

    if not verifier_agent():
        sys.exit(1)

    colonnes, moyennes, ecarts = charger_reference()
    print(f"\n  {len(colonnes)} features attendues par E-GraphSAGE")

    if args.csv:
        if not os.path.exists(args.csv):
            print(f"  CSV introuvable : {args.csv}")
            sys.exit(1)
        flux = flux_depuis_csv(args.csv, colonnes, args.n)
    else:
        flux = flux_depuis_distributions(colonnes, moyennes, ecarts, args.n)

    attendus = {}
    for f in flux:
        attendus[f["flow_id"]] = f.pop("_attendu", "?")

    print(f"\n  envoi de {len(flux)} flux…")
    res = post(f"{ANON_URL}/ingest", {"flows": flux, "source": "injecteur_flux"})
    print(f"  réponse : {res}")

    # --- comparaison étiquette réelle / verdict rendu ---
    if args.csv and attendus:
        try:
            with urllib.request.urlopen(f"{ANON_URL}/stats", timeout=20) as r:
                effort = json.load(r).get("effort") or []
            rendus = {e.get("flow_id"): e for e in effort}
            lignes, justes = [], 0
            for fid, attendu in attendus.items():
                e = rendus.get(fid)
                if not e:
                    continue
                obtenu = str(e.get("label", "?")).lower()
                etages = "+".join(e.get("stages", []))
                ok = (obtenu == attendu)
                justes += ok
                lignes.append((fid, attendu, obtenu, etages, ok))
            if lignes:
                print(f"\n  ÉTIQUETTE RÉELLE vs VERDICT ({justes}/{len(lignes)} concordants)")
                print(f"    {'flux':12s} {'réel':8s} {'verdict':8s} {'étages':16s}")
                for fid, att, obt, et, ok in lignes[:15]:
                    print(f"    {fid:12s} {att:8s} {obt:8s} {et:16s} {'✓' if ok else '✗'}")
                print("\n  ⚠️ Cet accord ne remplace pas une évaluation : l'échantillon")
                print("     est petit et non représentatif de la distribution réelle.")
        except Exception as e:
            print(f"  comparaison impossible : {e}")

    # état de la cascade après traitement
    try:
        with urllib.request.urlopen(f"{ANON_URL}/stats", timeout=20) as r:
            st = json.load(r)
        print(f"\n  compteurs : {st.get('counters')}")
        print(f"  cascade   : {st.get('cascade')}")
        effort = st.get("effort") or []
        if effort:
            print(f"\n  effort de cascade (5 derniers) :")
            for e in effort[-5:]:
                print(f"    {e}")
    except Exception:
        pass

    print(f"\n  Dashboard : http://127.0.0.1:8000/")
    print("\n  ⚠️ Ce test valide l'EXÉCUTION des GNN, pas leurs performances.")
    print("     Les chiffres de référence (Tor 0.906 / 0.892) ont été mesurés")
    print("     sur le dataset complet avec sa vérité terrain.")


if __name__ == "__main__":
    main()
