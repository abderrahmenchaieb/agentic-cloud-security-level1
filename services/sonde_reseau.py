"""
=============================================================================
SONDE RÉSEAU — capture → CICFlowMeter → agent Anonymization
=============================================================================
Brique manquante de la voie réseau. Alimente l'agent Anonymization en flux
porteurs des 76 features sur lesquelles E-GraphSAGE a été entraîné.

CHAÎNE
    trafic réseau → tshark/dumpcap → PCAP (tranches) → CICFlowMeter → CSV
                  → mapping des colonnes → POST /ingest vers l'agent

POURQUOI CICFlowMeter ET PAS UN CALCUL MAISON
    E-GraphSAGE a été entraîné sur CIC-Darknet2020, dont les features sont
    produites par CICFlowMeter. Réimplémenter les 76 définitions statistiques
    (IAT, sous-flux, drapeaux, tailles de segments…) exposerait à des écarts
    silencieux entre entraînement et inférence. Utiliser le MÊME outil garantit
    la cohérence — y compris sur ses imprécisions connues, qui affectent alors
    les deux côtés de la même façon.

⚠️ VERSION DE CICFlowMeter
    CIC-Darknet2020 utilise le nommage de CICFlowMeter V4.0 :
        « Total Fwd Packet » (singulier), « Total Bwd packets » (minuscule)
    CICIDS2017 utilise « Total Fwd Packets » / « Total Backward Packets ».
    Une mauvaise version produit des colonnes qui ne correspondent pas.
    Dépôt attendu : github.com/ahlashkari/CICFlowMeter (V4.0, Java).

PRÉREQUIS
    - tshark (paquet wireshark-cli) ou dumpcap
    - Java 8+ et CICFlowMeter installé
    - droits de capture (root, ou capability CAP_NET_RAW)

UTILISATION
    # capture continue par tranches de 60 s
    python3 sonde_reseau.py --interface eth0 --duree 60

    # traiter un PCAP déjà capturé
    python3 sonde_reseau.py --pcap capture.pcap

    # vérifier l'installation sans capturer
    python3 sonde_reseau.py --verifier

    # sur AWS (instance cible du Traffic Mirroring) : décapsulation VXLAN
    sudo python3 sonde_reseau.py --interface eth0 --vxlan --boucle

⚠️ AWS VPC TRAFFIC MIRRORING — CONTRAINTES VÉRIFIÉES
    - Type d'instance SOURCE : T3/T3a/T4g supportés ; **T2 NE L'EST PAS**
      (piège classique : t2.micro est l'instance free tier par défaut).
    - Le trafic mirroré est encapsulé en VXLAN sur UDP/4789 → utiliser --vxlan,
      sinon CICFlowMeter analyse l'enveloppe et non le trafic réel.
    - Instance CIBLE : 2 vCPU / 2 Gio minimum.
    - Facturation HORAIRE par session active, plus le transfert de données.
      La facturation continue tant que la session existe : il faut SUPPRIMER
      les sessions, pas seulement détacher l'interface.
=============================================================================
"""
from __future__ import annotations

import argparse
import csv
import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

ANON_URL   = os.environ.get("ANON_URL", "http://127.0.0.1:9003")
CICFM_HOME = os.environ.get("CICFLOWMETER_HOME", "/opt/CICFlowMeter")
CICFM_CMD  = os.environ.get("CICFLOWMETER_CMD", "")   # commande complète, si personnalisée

# --- AWS VPC Traffic Mirroring -----------------------------------------------
VXLAN_PORT = int(os.environ.get("VXLAN_PORT", "4789"))
VXLAN_IF   = os.environ.get("VXLAN_IF", "vxlan0")


def preparer_vxlan(interface_physique: str, port: int = VXLAN_PORT,
                   nom: str = VXLAN_IF) -> bool:
    """
    Crée une interface VXLAN qui DÉCAPSULE le trafic mirroré par AWS.

    ⚠️ POURQUOI C'EST INDISPENSABLE
        AWS VPC Traffic Mirroring encapsule le trafic copié en VXLAN sur
        UDP/4789. Capturer directement sur l'interface physique donnerait à
        CICFlowMeter des flux « instance source → instance cible, UDP 4789 » :
        toutes les features seraient calculées sur l'ENVELOPPE, pas sur le
        trafic réel. E-GraphSAGE classerait alors des flux qui n'existent pas.

        Cette interface décapsule au niveau noyau ; la capture se fait ensuite
        sur `vxlan0`, où circule le trafic d'origine.

    Sans effet hors AWS : inutile pour une capture locale sur VM.
    """
    if shutil.which("ip") is None:
        print("Commande `ip` introuvable (paquet iproute2).", file=sys.stderr)
        return False
    # déjà présente ?
    dejala = subprocess.run(["ip", "link", "show", nom],
                            capture_output=True).returncode == 0
    if dejala:
        print(f"[sonde] interface {nom} déjà présente")
        return True
    cmds = [
        ["ip", "link", "add", nom, "type", "vxlan", "id", "0",
         "dev", interface_physique, "dstport", str(port)],
        ["ip", "link", "set", nom, "up"],
    ]
    for c in cmds:
        r = subprocess.run(c, capture_output=True)
        if r.returncode != 0:
            err = r.stderr.decode(errors="ignore")[:160]
            print(f"Échec de `{' '.join(c)}` : {err}", file=sys.stderr)
            if "not permitted" in err.lower():
                print("→ droits root requis pour créer une interface VXLAN.",
                      file=sys.stderr)
            return False
    print(f"[sonde] interface VXLAN {nom} créée (décapsulation UDP/{port})")
    return True


def supprimer_vxlan(nom: str = VXLAN_IF) -> None:
    """Retire l'interface VXLAN créée."""
    subprocess.run(["ip", "link", "del", nom], capture_output=True)


# -----------------------------------------------------------------------------
# Colonnes attendues par le modèle (nommage CIC-Darknet2020 / CICFlowMeter V4)
# -----------------------------------------------------------------------------
def charger_colonnes_modele(config_path: str) -> list[str]:
    """Lit `feature_cols` depuis la configuration d'E-GraphSAGE."""
    import joblib
    return list(joblib.load(config_path).get("feature_cols", []))


def normaliser(nom: str) -> str:
    """
    Clé de comparaison insensible à la casse, aux espaces et aux underscores.
    Permet de rapprocher « Total Fwd Packet », « total_fwd_packet » et
    « Total Fwd  Packet » — les variantes rencontrées entre versions.
    """
    return "".join(c for c in nom.lower() if c.isalnum())


# -----------------------------------------------------------------------------
# Vérification de l'environnement
# -----------------------------------------------------------------------------
def trouver_tshark() -> str | None:
    for exe in ("tshark", "dumpcap", "tcpdump"):
        chemin = shutil.which(exe)
        if chemin:
            return chemin
    return None


def trouver_cicflowmeter() -> str | None:
    """Commande d'exécution de CICFlowMeter, ou None si introuvable."""
    if CICFM_CMD:
        return CICFM_CMD
    # script de lancement fourni par le dépôt
    for rel in ("bin/CICFlowMeter", "CICFlowMeter", "cfm"):
        p = os.path.join(CICFM_HOME, rel)
        if os.path.exists(p) and os.access(p, os.X_OK):
            return p
    # jar autonome
    jars = glob.glob(os.path.join(CICFM_HOME, "**", "*CICFlowMeter*.jar"),
                     recursive=True)
    if jars and shutil.which("java"):
        return f"java -jar {jars[0]}"
    return None


def verifier(config_path: str | None = None) -> bool:
    """Contrôle les prérequis et signale précisément ce qui manque."""
    ok = True
    print("=== Vérification de la sonde réseau ===\n")

    capture = trouver_tshark()
    if capture:
        print(f"  [OK] capture      : {capture}")
    else:
        print("  [X]  capture      : tshark/dumpcap/tcpdump introuvable")
        print("       → apt install wireshark-cli   (ou tcpdump)")
        ok = False

    java = shutil.which("java")
    print(f"  [{'OK' if java else 'X'}]  java         : {java or 'introuvable → apt install default-jre'}")
    ok = ok and bool(java)

    cfm = trouver_cicflowmeter()
    if cfm:
        print(f"  [OK] CICFlowMeter : {cfm}")
    else:
        print(f"  [X]  CICFlowMeter : introuvable dans {CICFM_HOME}")
        print("       → git clone https://github.com/ahlashkari/CICFlowMeter")
        print("         puis définir CICFLOWMETER_HOME")
        ok = False

    if os.geteuid() != 0:
        print("  [!]  droits       : la capture exige root ou CAP_NET_RAW")

    if config_path and os.path.exists(config_path):
        cols = charger_colonnes_modele(config_path)
        print(f"\n  Le modèle attend {len(cols)} features d'arête.")
        print(f"  Premières colonnes : {cols[:4]}")

    print("\n" + ("Sonde opérationnelle." if ok else "Prérequis manquants."))
    return ok


# -----------------------------------------------------------------------------
# Capture
# -----------------------------------------------------------------------------
def capturer(interface: str, duree: int, sortie: str) -> str | None:
    """Capture `duree` secondes de trafic vers un fichier PCAP."""
    exe = trouver_tshark()
    if exe is None:
        print("Aucun outil de capture disponible.", file=sys.stderr)
        return None

    base = os.path.basename(exe)
    if base in ("tshark", "dumpcap"):
        cmd = [exe, "-i", interface, "-a", f"duration:{duree}", "-w", sortie]
    else:  # tcpdump
        cmd = [exe, "-i", interface, "-G", str(duree), "-W", "1", "-w", sortie]

    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=duree + 30)
        return sortie if os.path.exists(sortie) else None
    except subprocess.CalledProcessError as e:
        err = e.stderr.decode(errors="ignore")[:200]
        print(f"Échec de la capture : {err}", file=sys.stderr)
        if "permission" in err.lower() or "denied" in err.lower():
            print("→ droits insuffisants : exécuter en root, ou\n"
                  "  setcap cap_net_raw,cap_net_admin+eip $(which dumpcap)",
                  file=sys.stderr)
        return None
    except subprocess.TimeoutExpired:
        print("Capture interrompue (délai dépassé).", file=sys.stderr)
        return None


# -----------------------------------------------------------------------------
# CICFlowMeter : PCAP → CSV
# -----------------------------------------------------------------------------
def pcap_vers_csv(pcap: str, dossier_sortie: str) -> str | None:
    """Lance CICFlowMeter sur un PCAP et renvoie le CSV produit."""
    cfm = trouver_cicflowmeter()
    if cfm is None:
        print(f"CICFlowMeter introuvable (CICFLOWMETER_HOME={CICFM_HOME}).",
              file=sys.stderr)
        return None

    os.makedirs(dossier_sortie, exist_ok=True)
    cmd = (cfm.split() if " " in cfm else [cfm]) + [pcap, dossier_sortie]
    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=600)
    except subprocess.CalledProcessError as e:
        print(f"CICFlowMeter a échoué : {e.stderr.decode(errors='ignore')[:200]}",
              file=sys.stderr)
        return None
    except subprocess.TimeoutExpired:
        print("CICFlowMeter : délai dépassé.", file=sys.stderr)
        return None

    csvs = glob.glob(os.path.join(dossier_sortie, "*.csv"))
    return max(csvs, key=os.path.getmtime) if csvs else None


# -----------------------------------------------------------------------------
# CSV → flux prêts pour l'agent
# -----------------------------------------------------------------------------
def csv_vers_flux(chemin_csv: str, colonnes_modele: list[str]) -> tuple[list[dict], dict]:
    """
    Convertit le CSV de CICFlowMeter en flux consommables par l'agent.

    Renvoie (flux, rapport) où `rapport` détaille la correspondance des
    colonnes — indispensable pour diagnostiquer une version incompatible
    AVANT que le GNN ne produise des prédictions douteuses.
    """
    flux: list[dict] = []
    with open(chemin_csv, newline="", encoding="utf-8", errors="ignore") as fh:
        lecteur = csv.DictReader(fh)
        entetes = lecteur.fieldnames or []

        # rapprochement tolérant aux variantes de nommage
        index = {normaliser(h): h for h in entetes}
        correspondance, manquantes = {}, []
        for col in colonnes_modele:
            reelle = index.get(normaliser(col))
            if reelle:
                correspondance[col] = reelle
            else:
                manquantes.append(col)

        for i, ligne in enumerate(lecteur):
            feats = {}
            for col_modele, col_csv in correspondance.items():
                try:
                    v = float(ligne.get(col_csv, 0) or 0)
                    feats[col_modele] = 0.0 if v != v or abs(v) == float("inf") else v
                except (TypeError, ValueError):
                    feats[col_modele] = 0.0
            flux.append({
                "flow_id": ligne.get("Flow ID") or f"flow-{i}",
                "src_ip": ligne.get("Src IP") or ligne.get("Source IP") or "",
                "dst_ip": ligne.get("Dst IP") or ligne.get("Destination IP") or "",
                "src_port": _entier(ligne.get("Src Port") or ligne.get("Source Port")),
                "dst_port": _entier(ligne.get("Dst Port") or ligne.get("Destination Port")),
                "protocol": ligne.get("Protocol") or "",
                "timestamp": ligne.get("Timestamp") or "",
                "features": feats,
            })

    rapport = {"colonnes_csv": len(entetes),
               "attendues": len(colonnes_modele),
               "correspondantes": len(correspondance),
               "manquantes": manquantes[:10],
               "flux": len(flux)}
    return flux, rapport


def _entier(v):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return None


def envoyer(flux: list[dict]) -> dict | None:
    """Transmet les flux à l'agent Anonymization."""
    if not flux:
        return {"flows": 0}
    data = json.dumps({"flows": flux, "source": "sonde_reseau"}).encode("utf-8")
    req = urllib.request.Request(f"{ANON_URL}/ingest", data=data,
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read().decode("utf-8") or "{}")
    except Exception as e:
        print(f"Agent Anonymization injoignable ({ANON_URL}) : {e}", file=sys.stderr)
        return None


# -----------------------------------------------------------------------------
def traiter_pcap(pcap: str, colonnes: list[str], verbeux: bool = True) -> dict | None:
    """PCAP → CSV → flux → agent."""
    with tempfile.TemporaryDirectory() as tmp:
        chemin_csv = pcap_vers_csv(pcap, tmp)
        if chemin_csv is None:
            return None
        flux, rapport = csv_vers_flux(chemin_csv, colonnes)
        if verbeux:
            print(f"  CSV : {rapport['colonnes_csv']} colonnes | "
                  f"correspondance {rapport['correspondantes']}/{rapport['attendues']} | "
                  f"{rapport['flux']} flux")
            if rapport["manquantes"]:
                print(f"  ⚠️ colonnes absentes du CSV : {rapport['manquantes']}")
                print("     → version de CICFlowMeter probablement incompatible "
                      "(V4.0 attendue)")
        return envoyer(flux)


def main() -> None:
    p = argparse.ArgumentParser(description="Sonde réseau tshark + CICFlowMeter")
    p.add_argument("--interface", "-i", default="eth0", help="interface à écouter")
    p.add_argument("--duree", "-d", type=int, default=60,
                   help="durée d'une tranche de capture, en secondes")
    p.add_argument("--pcap", help="traiter ce PCAP au lieu de capturer")
    p.add_argument("--boucle", action="store_true",
                   help="capturer en continu, tranche après tranche")
    p.add_argument("--config", default=os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "models", "egraphsage_config.pkl"))
    p.add_argument("--verifier", action="store_true",
                   help="contrôler les prérequis sans capturer")
    p.add_argument("--vxlan", action="store_true",
                   help="mode AWS Traffic Mirroring : décapsule le VXLAN "
                        "(UDP/4789) avant analyse. Indispensable sur AWS, "
                        "inutile pour une capture locale.")
    args = p.parse_args()

    if args.verifier:
        sys.exit(0 if verifier(args.config) else 1)

    if not os.path.exists(args.config):
        print(f"Configuration du modèle introuvable : {args.config}", file=sys.stderr)
        sys.exit(1)
    colonnes = charger_colonnes_modele(args.config)
    print(f"[sonde] {len(colonnes)} features attendues par E-GraphSAGE")

    if args.pcap:
        res = traiter_pcap(args.pcap, colonnes)
        print(f"[sonde] agent → {res}")
        return

    interface_capture = args.interface
    if args.vxlan:
        # sur AWS, le trafic mirroré arrive encapsulé : on capture sur
        # l'interface VXLAN (décapsulée), pas sur l'interface physique
        if not preparer_vxlan(args.interface):
            print("Impossible de préparer la décapsulation VXLAN.", file=sys.stderr)
            sys.exit(1)
        interface_capture = VXLAN_IF

    print(f"[sonde] capture sur {interface_capture}, tranches de {args.duree}s "
          f"→ {ANON_URL}")
    while True:
        with tempfile.TemporaryDirectory() as tmp:
            pcap = os.path.join(tmp, f"capture-{int(time.time())}.pcap")
            if capturer(interface_capture, args.duree, pcap):
                res = traiter_pcap(pcap, colonnes)
                print(f"[sonde] {time.strftime('%H:%M:%S')} → {res}", flush=True)
            else:
                time.sleep(5)
        if not args.boucle:
            break


if __name__ == "__main__":
    main()
