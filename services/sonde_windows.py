"""
=============================================================================
SONDE WINDOWS UNIFIÉE — journal Sysmon + capture réseau
=============================================================================
UN SEUL programme à installer sur chaque machine Windows surveillée. Il
alimente les deux voies du système :

    journal Sysmon  ──► agent COLLECT        (détection de menace + intégrité)
    trafic réseau   ──► agent ANONYMIZATION  (détection VPN/Tor)

POURQUOI UNIFIER
    Les deux voies observent la MÊME machine. Deux programmes distincts
    imposeraient deux installations, deux services à surveiller, deux
    configurations à tenir cohérentes — et le risque qu'une voie s'arrête
    sans qu'on s'en aperçoive. Ici, un seul exécutable, un seul état de santé.

ARCHITECTURE INTERNE
    Deux fils d'exécution indépendants, un par voie. La panne d'une voie
    n'interrompt pas l'autre : si CICFlowMeter est absent, la remontée des
    logs continue, et inversement.

        fil 1 : wevtutil / win32evtlog → EventID Sysmon → POST /ingest
        fil 2 : dumpcap → PCAP → CICFlowMeter → 76 features → POST /ingest

PRÉREQUIS
    - Sysmon installé et configuré (config SwiftOnSecurity recommandée)
    - Wireshark (dumpcap) pour la capture
    - Java + CICFlowMeter V4.0 pour les features de flux
    - droits administrateur (lecture du journal + capture)

UTILISATION
    python sonde_windows.py --verifier              # contrôle des prérequis
    python sonde_windows.py                         # les deux voies
    python sonde_windows.py --voie logs             # journal seul
    python sonde_windows.py --voie reseau           # capture seule

EMPAQUETAGE EN EXÉCUTABLE UNIQUE
    pip install pyinstaller
    pyinstaller --onefile --name sonde_windows sonde_windows.py
    → dist/sonde_windows.exe   (aucun Python requis sur la machine cible)
=============================================================================
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from datetime import datetime, timedelta

COLLECT_URL = os.environ.get("COLLECT_URL", "")
ANON_URL    = os.environ.get("ANON_URL", "")
CICFM_HOME  = os.environ.get("CICFLOWMETER_HOME", r"C:\CICFlowMeter")


# =============================================================================
# DÉCOUVERTE AUTOMATIQUE DE L'HÔTE
# =============================================================================
def _passerelle_par_defaut() -> str | None:
    """
    Passerelle de la VM. En NAT (VirtualBox/VMware), c'est l'hôte lui-même.
    Aucun paquet n'est réellement émis : `connect` sur UDP ne fait que
    sélectionner l'interface de sortie.
    """
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(("8.8.8.8", 80))
        local = s.getsockname()[0]
        s.close()
        octets = local.split(".")
        return ".".join(octets[:3] + ["1"])   # convention : .1 = passerelle
    except Exception:
        return None


def _repond(base: str, port: int, delai: float = 1.5) -> bool:
    try:
        with urllib.request.urlopen(f"http://{base}:{port}/health",
                                    timeout=delai) as r:
            return r.status == 200
    except Exception:
        return False


def decouvrir_hote(port_sonde: int = 9001) -> str | None:
    """
    Cherche l'adresse à laquelle le système répond.

    Ce qui est automatisable : trouver l'hôte parmi les adresses usuelles.
    Ce qui ne l'est PAS : le mode réseau de la VM. En NAT pur, l'hôte n'est
    pas joignable depuis la VM — il faut ajouter une carte « réseau hôte
    uniquement » dans les réglages de la machine virtuelle, VM éteinte.
    """
    candidats = []
    passerelle = _passerelle_par_defaut()
    if passerelle:
        candidats.append(passerelle)
    candidats += [
        "192.168.56.1",   # host-only VirtualBox (défaut)
        "192.168.1.1",
        "172.16.42.1",
        "192.168.100.1",  # host-only VMware fréquent
        "host.docker.internal",
        "127.0.0.1",      # sonde et système sur la même machine
    ]

    vus = set()
    for base in candidats:
        if base in vus:
            continue
        vus.add(base)
        if _repond(base, port_sonde):
            print(f"[sonde] système détecté sur {base}", flush=True)
            return base

    print("[sonde] système INTROUVABLE. Adresses testées : "
          f"{', '.join(sorted(vus))}", flush=True)
    print("[sonde] vérifier que :", flush=True)
    print("        1. la pile Docker tourne sur l'hôte "
          "(docker compose ps)", flush=True)
    print("        2. la VM dispose d'une carte « réseau hôte uniquement » "
          "(NAT seul ne suffit pas)", flush=True)
    print("        3. le pare-feu de l'hôte autorise les ports 9001 et 9003",
          flush=True)
    print("        4. sinon, forcer l'adresse : "
          "set COLLECT_URL=http://<ip-hote>:9001", flush=True)
    return None


def resoudre_destinations() -> None:
    """
    Fixe COLLECT_URL et ANON_URL. Les variables d'environnement priment ;
    à défaut, l'hôte est recherché automatiquement.
    """
    global COLLECT_URL, ANON_URL
    if COLLECT_URL and ANON_URL:
        return
    hote = decouvrir_hote()
    if hote is None:
        # repli : la sonde démarrera et signalera les échecs d'envoi
        hote = "127.0.0.1"
    COLLECT_URL = COLLECT_URL or f"http://{hote}:9001"
    ANON_URL    = ANON_URL or f"http://{hote}:9003"

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
LOT_MAX = 500          # événements par envoi
INTERVALLE_LOGS = 10   # secondes entre deux lectures du journal
DUREE_CAPTURE = 60     # secondes par tranche de capture


def post_json(url: str, payload: dict, timeout: float = 60.0):
    data = json.dumps(payload, default=str).encode("utf-8")
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8")
            return json.loads(body) if body else {}
    except Exception as e:
        print(f"  [!] {url} injoignable : {e}", flush=True)
        return None


# =============================================================================
# VOIE 1 — JOURNAL SYSMON
# =============================================================================
def lire_sysmon_wevtutil(depuis: datetime, maximum: int = LOT_MAX) -> list[dict]:
    """
    Lit le journal Sysmon via `wevtutil` (présent nativement sur Windows).

    Le format XML de Sysmon place les champs dans <Data Name="...">valeur</Data>.
    On les remonte à plat pour correspondre à ce qu'attend le mapper du Collect
    (`EventID`, `UtcTime`, `Computer`, `ProcessGuid`, `Image`…).
    """
    if shutil.which("wevtutil") is None:
        return []
    # filtre XPath : uniquement les événements postérieurs à `depuis`
    delta_ms = int((datetime.utcnow() - depuis).total_seconds() * 1000) + 1000
    requete = f"*[System[TimeCreated[timediff(@SystemTime) <= {delta_ms}]]]"
    cmd = ["wevtutil", "qe", SYSMON_CHANNEL, f"/q:{requete}",
           f"/c:{maximum}", "/f:xml", "/e:Events"]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=60)
        if r.returncode != 0:
            return []
        return _parser_xml_sysmon(r.stdout.decode("utf-8", errors="ignore"))
    except Exception:
        return []


def _parser_xml_sysmon(xml: str) -> list[dict]:
    """XML Sysmon → liste de dicts plats."""
    import xml.etree.ElementTree as ET
    try:
        racine = ET.fromstring(xml)
    except ET.ParseError:
        return []

    evenements = []
    for ev in racine:
        d: dict[str, str] = {}
        for elem in ev.iter():
            tag = elem.tag.split("}")[-1]
            if tag == "EventID" and elem.text:
                d["EventID"] = elem.text.strip()
            elif tag == "Computer" and elem.text:
                d["Computer"] = elem.text.strip()
            elif tag == "TimeCreated":
                st = elem.attrib.get("SystemTime")
                if st:
                    d["_SystemTime"] = st
            elif tag == "EventRecordID" and elem.text:
                d["RecordNumber"] = elem.text.strip()
            elif tag == "Data":
                nom = elem.attrib.get("Name")
                if nom:
                    d[nom] = (elem.text or "").strip()
        if "EventID" in d:
            # le mapper attend UtcTime ; Sysmon le fournit, sinon on retombe
            # sur l'horodatage système de l'enregistrement
            if "UtcTime" not in d and "_SystemTime" in d:
                d["UtcTime"] = d["_SystemTime"].replace("T", " ").rstrip("Z")
            d.pop("_SystemTime", None)
            evenements.append(d)
    return evenements


def voie_logs(intervalle: int = INTERVALLE_LOGS, une_fois: bool = False) -> None:
    """Fil d'exécution : journal Sysmon → agent Collect."""
    print(f"[logs] démarrage — {SYSMON_CHANNEL} → {COLLECT_URL}", flush=True)
    dernier = datetime.utcnow() - timedelta(seconds=intervalle)
    total = 0
    while True:
        maintenant = datetime.utcnow()
        evenements = lire_sysmon_wevtutil(dernier)
        dernier = maintenant
        if evenements:
            res = post_json(f"{COLLECT_URL}/ingest", {"events": evenements})
            total += len(evenements)
            print(f"[logs] {time.strftime('%H:%M:%S')} — {len(evenements)} "
                  f"événement(s) (total {total}) → {res}", flush=True)
        if une_fois:
            return
        time.sleep(intervalle)


# =============================================================================
# VOIE 2 — CAPTURE RÉSEAU
# =============================================================================
def trouver_dumpcap() -> str | None:
    for chemin in (shutil.which("dumpcap"), shutil.which("tshark"),
                   r"C:\Program Files\Wireshark\dumpcap.exe",
                   r"C:\Program Files\Wireshark\tshark.exe"):
        if chemin and os.path.exists(chemin):
            return chemin
    return None


def trouver_cicflowmeter() -> str | None:
    import glob
    for rel in ("bin/CICFlowMeter.bat", "bin/CICFlowMeter", "CICFlowMeter.bat"):
        p = os.path.join(CICFM_HOME, rel)
        if os.path.exists(p):
            return p
    jars = glob.glob(os.path.join(CICFM_HOME, "**", "*CICFlowMeter*.jar"),
                     recursive=True)
    if jars and shutil.which("java"):
        return f"java -jar {jars[0]}"
    return None


def voie_reseau(interface: str, duree: int = DUREE_CAPTURE,
                une_fois: bool = False) -> None:
    """Fil d'exécution : capture → CICFlowMeter → agent Anonymization."""
    capture = trouver_dumpcap()
    cfm = trouver_cicflowmeter()
    if capture is None or cfm is None:
        print(f"[reseau] voie DÉSACTIVÉE — "
              f"{'dumpcap' if capture is None else 'CICFlowMeter'} introuvable",
              flush=True)
        return

    # colonnes attendues par E-GraphSAGE (nommage CIC-Darknet2020)
    colonnes = _colonnes_modele()
    print(f"[reseau] démarrage — {interface}, tranches de {duree}s → {ANON_URL} "
          f"({len(colonnes)} features)", flush=True)

    while True:
        with tempfile.TemporaryDirectory() as tmp:
            pcap = os.path.join(tmp, "capture.pcap")
            cmd = [capture, "-i", interface, "-a", f"duration:{duree}", "-w", pcap]
            try:
                subprocess.run(cmd, check=True, capture_output=True,
                               timeout=duree + 30)
            except Exception as e:
                print(f"[reseau] échec de capture : {str(e)[:120]}", flush=True)
                time.sleep(5)
                if une_fois:
                    return
                continue

            flux = _pcap_vers_flux(pcap, cfm, tmp, colonnes)
            if flux:
                res = post_json(f"{ANON_URL}/ingest", {"flows": flux,
                                                       "source": "sonde_windows"})
                print(f"[reseau] {time.strftime('%H:%M:%S')} — {len(flux)} flux "
                      f"→ {res}", flush=True)
        if une_fois:
            return


def _colonnes_modele() -> list[str]:
    """Colonnes attendues, lues depuis la config du modèle si disponible."""
    for chemin in (os.environ.get("EGRAPHSAGE_CONFIG", ""),
                   os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "models", "egraphsage_config.pkl")):
        if chemin and os.path.exists(chemin):
            try:
                import joblib
                return list(joblib.load(chemin).get("feature_cols", []))
            except Exception:
                pass
    return []   # sans config : on transmet toutes les colonnes numériques


def _pcap_vers_flux(pcap: str, cfm: str, tmp: str, colonnes: list[str]) -> list[dict]:
    """PCAP → CICFlowMeter → flux prêts pour l'agent."""
    import csv, glob
    sortie = os.path.join(tmp, "csv")
    os.makedirs(sortie, exist_ok=True)
    cmd = (cfm.split() if " " in cfm else [cfm]) + [pcap, sortie]
    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=600)
    except Exception as e:
        print(f"[reseau] CICFlowMeter a échoué : {str(e)[:120]}", flush=True)
        return []

    fichiers = glob.glob(os.path.join(sortie, "*.csv"))
    if not fichiers:
        return []

    def cle(nom): return "".join(c for c in nom.lower() if c.isalnum())

    flux = []
    with open(max(fichiers, key=os.path.getmtime), newline="",
              encoding="utf-8", errors="ignore") as fh:
        lecteur = csv.DictReader(fh)
        index = {cle(h): h for h in (lecteur.fieldnames or [])}
        corresp = {c: index[cle(c)] for c in colonnes if cle(c) in index}
        for i, ligne in enumerate(lecteur):
            feats = {}
            for col, src in corresp.items():
                try:
                    v = float(ligne.get(src, 0) or 0)
                    feats[col] = 0.0 if v != v or abs(v) == float("inf") else v
                except (TypeError, ValueError):
                    feats[col] = 0.0
            flux.append({
                "flow_id": ligne.get("Flow ID") or f"flow-{i}",
                "src_ip": ligne.get("Src IP") or "",
                "dst_ip": ligne.get("Dst IP") or "",
                "src_port": _entier(ligne.get("Src Port")),
                "dst_port": _entier(ligne.get("Dst Port")),
                "protocol": ligne.get("Protocol") or "",
                "timestamp": ligne.get("Timestamp") or "",
                "features": feats,
            })
    return flux


def _entier(v):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return None


# =============================================================================
def verifier() -> bool:
    """Contrôle les prérequis des DEUX voies et indique ce qui manque."""
    print("=== Sonde Windows — vérification ===\n")
    ok_logs = ok_reseau = True

    print("VOIE 1 — journal Sysmon")
    wev = shutil.which("wevtutil")
    print(f"  [{'OK' if wev else 'X'}] wevtutil : {wev or 'introuvable (Windows requis)'}")
    ok_logs = bool(wev)
    if wev:
        r = subprocess.run(["wevtutil", "gl", SYSMON_CHANNEL], capture_output=True)
        present = r.returncode == 0
        print(f"  [{'OK' if present else 'X'}] canal Sysmon : "
              f"{SYSMON_CHANNEL if present else 'absent → installer Sysmon'}")
        ok_logs = ok_logs and present

    print("\nVOIE 2 — capture réseau")
    cap = trouver_dumpcap()
    print(f"  [{'OK' if cap else 'X'}] dumpcap : {cap or 'introuvable → installer Wireshark'}")
    java = shutil.which("java")
    print(f"  [{'OK' if java else 'X'}] java    : {java or 'introuvable → installer un JRE'}")
    cfm = trouver_cicflowmeter()
    print(f"  [{'OK' if cfm else 'X'}] CICFlowMeter : {cfm or f'introuvable dans {CICFM_HOME}'}")
    ok_reseau = all([cap, java, cfm])

    print("\nDestinations")
    for nom, url in (("Collect", COLLECT_URL), ("Anonymization", ANON_URL)):
        joignable = False
        try:
            with urllib.request.urlopen(f"{url}/health", timeout=3) as r:
                joignable = r.status == 200
        except Exception:
            pass
        print(f"  [{'OK' if joignable else '!'}] {nom:14s} : {url}"
              f"{'' if joignable else '  (injoignable)'}")

    print(f"\nVoie logs   : {'opérationnelle' if ok_logs else 'indisponible'}")
    print(f"Voie réseau : {'opérationnelle' if ok_reseau else 'indisponible'}")
    return ok_logs or ok_reseau


def main() -> None:
    p = argparse.ArgumentParser(
        description="Sonde Windows unifiée (journal Sysmon + capture réseau)")
    p.add_argument("--voie", choices=("logs", "reseau", "deux"), default="deux",
                   help="voie à activer (défaut : les deux)")
    p.add_argument("--interface", "-i", default="1",
                   help="interface de capture (numéro dumpcap sous Windows)")
    p.add_argument("--intervalle", type=int, default=INTERVALLE_LOGS,
                   help="secondes entre deux lectures du journal")
    p.add_argument("--duree", type=int, default=DUREE_CAPTURE,
                   help="secondes par tranche de capture")
    p.add_argument("--une-fois", action="store_true",
                   help="un seul cycle, puis sortie (test)")
    p.add_argument("--verifier", action="store_true",
                   help="contrôler les prérequis sans rien envoyer")
    args = p.parse_args()

    resoudre_destinations()

    if args.verifier:
        sys.exit(0 if verifier() else 1)

    fils = []
    if args.voie in ("logs", "deux"):
        fils.append(threading.Thread(target=voie_logs,
                                     args=(args.intervalle, args.une_fois),
                                     daemon=True))
    if args.voie in ("reseau", "deux"):
        fils.append(threading.Thread(target=voie_reseau,
                                     args=(args.interface, args.duree, args.une_fois),
                                     daemon=True))
    if not fils:
        print("Aucune voie activée.", file=sys.stderr)
        sys.exit(1)

    print(f"=== Sonde Windows — {len(fils)} voie(s) active(s) ===", flush=True)
    for f in fils:
        f.start()
    try:
        # les voies sont indépendantes : l'arrêt de l'une ne stoppe pas l'autre
        while any(f.is_alive() for f in fils):
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[sonde] arrêt demandé", flush=True)


if __name__ == "__main__":
    main()
