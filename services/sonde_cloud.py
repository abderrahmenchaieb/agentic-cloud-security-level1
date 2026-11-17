"""
=============================================================================
SONDE CLOUD UNIFIÉE — CloudTrail + trafic mirroré (AWS)
=============================================================================
Pendant cloud de `sonde_windows.py`. UN SEUL programme, déployé sur
l'instance cible du Traffic Mirroring, qui alimente les deux voies :

    CloudTrail (S3)      ──► agent COLLECT        (plan de contrôle)
    trafic mirroré       ──► agent ANONYMIZATION  (plan de données)

POURQUOI DEUX SOURCES CÔTÉ CLOUD
    CloudTrail est un journal de PLAN DE CONTRÔLE : il enregistre les appels
    d'API AWS (qui a fait quoi), avec une `sourceIPAddress` mais AUCUNE
    statistique de flux. Il ne peut donc pas alimenter E-GraphSAGE.

    Le VPC Traffic Mirroring copie le PLAN DE DONNÉES — le trafic réseau réel.
    Traité par CICFlowMeter, il fournit les 76 features attendues par le
    modèle. C'est ce qui donne au cloud la PARITÉ avec la voie Windows.

⚠️ CONTRAINTES AWS VÉRIFIÉES
    - Instance SOURCE : T3 / T3a / T4g supportés. **T2 NE L'EST PAS**
      (piège classique : t2.micro est l'instance free tier par défaut).
    - Le trafic mirroré arrive encapsulé en VXLAN sur UDP/4789. Sans
      décapsulation, CICFlowMeter analyserait l'ENVELOPPE et non le trafic
      réel — sans aucune erreur visible. D'où l'interface VXLAN créée ici.
    - Instance CIBLE : 2 vCPU / 2 Gio minimum.
    - Facturation HORAIRE par session active, plus le transfert de données.
      Elle continue tant que la session EXISTE : il faut SUPPRIMER les
      sessions, pas seulement détacher l'interface réseau.

PRÉREQUIS
    - accès en lecture au bucket S3 des logs CloudTrail (rôle IAM ou clés)
    - tshark/dumpcap, Java, CICFlowMeter V4.0
    - droits root (création de l'interface VXLAN, capture)

UTILISATION
    python3 sonde_cloud.py --verifier
    sudo python3 sonde_cloud.py --bucket mon-bucket-cloudtrail --interface eth0
    python3 sonde_cloud.py --voie cloudtrail --dossier ./logs_locaux
=============================================================================
"""
from __future__ import annotations

import argparse
import glob
import gzip
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

COLLECT_URL = os.environ.get("COLLECT_URL", "")
ANON_URL    = os.environ.get("ANON_URL", "")

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

CICFM_HOME  = os.environ.get("CICFLOWMETER_HOME", "/opt/CICFlowMeter")
VXLAN_PORT  = int(os.environ.get("VXLAN_PORT", "4789"))
VXLAN_IF    = os.environ.get("VXLAN_IF", "vxlan0")

INTERVALLE_CLOUDTRAIL = 60   # secondes entre deux relevés S3
DUREE_CAPTURE = 60
LOT_MAX = 500


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
# VOIE 1 — CLOUDTRAIL
# =============================================================================
def lire_cloudtrail_s3(bucket: str, prefixe: str, depuis: float) -> list[dict]:
    """
    Relève les objets CloudTrail déposés dans S3 depuis `depuis`.
    Nécessite boto3 et des droits de lecture sur le bucket.
    """
    try:
        import boto3
    except ImportError:
        print("[cloudtrail] boto3 absent → pip install boto3", flush=True)
        return []

    s3 = boto3.client("s3")
    evenements: list[dict] = []
    try:
        pages = s3.get_paginator("list_objects_v2").paginate(
            Bucket=bucket, Prefix=prefixe)
        for page in pages:
            for obj in page.get("Contents", []):
                if obj["LastModified"].timestamp() <= depuis:
                    continue
                corps = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
                if obj["Key"].endswith(".gz"):
                    corps = gzip.decompress(corps)
                evenements.extend(json.loads(corps).get("Records", []))
                if len(evenements) >= LOT_MAX:
                    return evenements
    except Exception as e:
        print(f"[cloudtrail] lecture S3 impossible : {str(e)[:150]}", flush=True)
    return evenements


def lire_cloudtrail_local(dossier: str, deja_vus: set) -> list[dict]:
    """Lit des fichiers CloudTrail locaux (tests, ou export manuel)."""
    evenements: list[dict] = []
    motifs = ("**/*.json.gz", "**/*.json")
    for motif in motifs:
        for chemin in glob.glob(os.path.join(dossier, motif), recursive=True):
            if chemin in deja_vus:
                continue
            deja_vus.add(chemin)
            try:
                ouvrir = gzip.open if chemin.endswith(".gz") else open
                with ouvrir(chemin, "rt", encoding="utf-8", errors="ignore") as fh:
                    evenements.extend(json.load(fh).get("Records", []))
            except Exception:
                continue
    return evenements


def voie_cloudtrail(bucket: str | None, prefixe: str, dossier: str | None,
                    intervalle: int, une_fois: bool) -> None:
    """Fil d'exécution : CloudTrail → agent Collect."""
    source = f"s3://{bucket}/{prefixe}" if bucket else dossier
    print(f"[cloudtrail] démarrage — {source} → {COLLECT_URL}", flush=True)
    depuis = time.time() - intervalle
    deja_vus: set = set()
    total = 0
    while True:
        if bucket:
            evenements = lire_cloudtrail_s3(bucket, prefixe, depuis)
            depuis = time.time()
        else:
            evenements = lire_cloudtrail_local(dossier or ".", deja_vus)

        if evenements:
            # le Collect route les événements cloud via son adaptateur
            res = post_json(f"{COLLECT_URL}/ingest",
                            {"events": evenements, "source": "cloudtrail"})
            total += len(evenements)
            print(f"[cloudtrail] {time.strftime('%H:%M:%S')} — "
                  f"{len(evenements)} événement(s) (total {total}) → {res}",
                  flush=True)
        if une_fois:
            return
        time.sleep(intervalle)


# =============================================================================
# VOIE 2 — TRAFIC MIRRORÉ (VXLAN)
# =============================================================================
def preparer_vxlan(interface: str, port: int = VXLAN_PORT,
                   nom: str = VXLAN_IF) -> bool:
    """
    Crée l'interface qui DÉCAPSULE le trafic mirroré.
    Sans elle, CICFlowMeter verrait des flux UDP/4789 vers cette instance au
    lieu du trafic réel — features calculées sur l'enveloppe, silencieusement.
    """
    if shutil.which("ip") is None:
        print("[mirroring] commande `ip` absente (paquet iproute2)", flush=True)
        return False
    if subprocess.run(["ip", "link", "show", nom],
                      capture_output=True).returncode == 0:
        print(f"[mirroring] interface {nom} déjà présente", flush=True)
        return True
    for cmd in (["ip", "link", "add", nom, "type", "vxlan", "id", "0",
                 "dev", interface, "dstport", str(port)],
                ["ip", "link", "set", nom, "up"]):
        r = subprocess.run(cmd, capture_output=True)
        if r.returncode != 0:
            err = r.stderr.decode(errors="ignore")[:150]
            print(f"[mirroring] échec `{' '.join(cmd)}` : {err}", flush=True)
            if "not permitted" in err.lower():
                print("[mirroring] → droits root requis", flush=True)
            return False
    print(f"[mirroring] interface VXLAN {nom} créée (décapsulation UDP/{port})",
          flush=True)
    return True


def trouver_capture() -> str | None:
    for exe in ("dumpcap", "tshark", "tcpdump"):
        p = shutil.which(exe)
        if p:
            return p
    return None


def trouver_cicflowmeter() -> str | None:
    for rel in ("bin/CICFlowMeter", "CICFlowMeter", "cfm"):
        p = os.path.join(CICFM_HOME, rel)
        if os.path.exists(p) and os.access(p, os.X_OK):
            return p
    jars = glob.glob(os.path.join(CICFM_HOME, "**", "*CICFlowMeter*.jar"),
                     recursive=True)
    if jars and shutil.which("java"):
        return f"java -jar {jars[0]}"
    return None


def voie_mirroring(interface: str, duree: int, une_fois: bool) -> None:
    """Fil d'exécution : trafic mirroré → CICFlowMeter → Anonymization."""
    capture = trouver_capture()
    cfm = trouver_cicflowmeter()
    if capture is None or cfm is None:
        manquant = "outil de capture" if capture is None else "CICFlowMeter"
        print(f"[mirroring] voie DÉSACTIVÉE — {manquant} introuvable", flush=True)
        return
    if not preparer_vxlan(interface):
        print("[mirroring] voie DÉSACTIVÉE — décapsulation VXLAN impossible",
              flush=True)
        return

    colonnes = _colonnes_modele()
    print(f"[mirroring] démarrage — {VXLAN_IF}, tranches de {duree}s → "
          f"{ANON_URL} ({len(colonnes)} features)", flush=True)

    while True:
        with tempfile.TemporaryDirectory() as tmp:
            pcap = os.path.join(tmp, "mirror.pcap")
            cmd = [capture, "-i", VXLAN_IF, "-a", f"duration:{duree}", "-w", pcap]
            try:
                subprocess.run(cmd, check=True, capture_output=True,
                               timeout=duree + 30)
            except Exception as e:
                print(f"[mirroring] échec de capture : {str(e)[:120]}", flush=True)
                time.sleep(5)
                if une_fois:
                    return
                continue
            flux = _pcap_vers_flux(pcap, cfm, tmp, colonnes)
            if flux:
                res = post_json(f"{ANON_URL}/ingest",
                                {"flows": flux, "source": "sonde_cloud"})
                print(f"[mirroring] {time.strftime('%H:%M:%S')} — {len(flux)} flux "
                      f"→ {res}", flush=True)
        if une_fois:
            return


def _colonnes_modele() -> list[str]:
    for chemin in (os.environ.get("EGRAPHSAGE_CONFIG", ""),
                   os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "models", "egraphsage_config.pkl")):
        if chemin and os.path.exists(chemin):
            try:
                import joblib
                return list(joblib.load(chemin).get("feature_cols", []))
            except Exception:
                pass
    return []


def _pcap_vers_flux(pcap: str, cfm: str, tmp: str, colonnes: list[str]) -> list[dict]:
    import csv
    sortie = os.path.join(tmp, "csv")
    os.makedirs(sortie, exist_ok=True)
    cmd = (cfm.split() if " " in cfm else [cfm]) + [pcap, sortie]
    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=600)
    except Exception as e:
        print(f"[mirroring] CICFlowMeter a échoué : {str(e)[:120]}", flush=True)
        return []
    fichiers = glob.glob(os.path.join(sortie, "*.csv"))
    if not fichiers:
        return []

    def cle(n): return "".join(c for c in n.lower() if c.isalnum())

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
def verifier(bucket: str | None) -> bool:
    print("=== Sonde cloud — vérification ===\n")

    print("VOIE 1 — CloudTrail")
    try:
        import boto3  # noqa: F401
        print("  [OK] boto3")
        ok_ct = True
    except ImportError:
        print("  [X]  boto3 → pip install boto3")
        ok_ct = False
    if bucket and ok_ct:
        try:
            import boto3
            boto3.client("s3").head_bucket(Bucket=bucket)
            print(f"  [OK] bucket accessible : {bucket}")
        except Exception as e:
            print(f"  [X]  bucket {bucket} : {str(e)[:110]}")
            ok_ct = False

    print("\nVOIE 2 — trafic mirroré")
    cap = trouver_capture()
    print(f"  [{'OK' if cap else 'X'}] capture      : {cap or 'introuvable → apt install wireshark-cli'}")
    java = shutil.which("java")
    print(f"  [{'OK' if java else 'X'}] java         : {java or 'introuvable → apt install default-jre'}")
    cfm = trouver_cicflowmeter()
    print(f"  [{'OK' if cfm else 'X'}] CICFlowMeter : {cfm or f'introuvable dans {CICFM_HOME}'}")
    root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False
    print(f"  [{'OK' if root else '!'}] droits root  : "
          f"{'oui' if root else 'non — requis pour VXLAN et capture'}")
    ok_mir = all([cap, java, cfm])

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

    print("\n⚠️ Rappel AWS : instance source en T3/T3a/T4g (T2 non supporté),")
    print("   et SUPPRIMER les sessions de mirroring pour arrêter la facturation.")
    print(f"\nVoie CloudTrail : {'opérationnelle' if ok_ct else 'indisponible'}")
    print(f"Voie mirroring  : {'opérationnelle' if ok_mir else 'indisponible'}")
    return ok_ct or ok_mir


def main() -> None:
    p = argparse.ArgumentParser(
        description="Sonde cloud unifiée (CloudTrail + trafic mirroré)")
    p.add_argument("--voie", choices=("cloudtrail", "mirroring", "deux"),
                   default="deux")
    p.add_argument("--bucket", help="bucket S3 des logs CloudTrail")
    p.add_argument("--prefixe", default="AWSLogs/", help="préfixe des objets S3")
    p.add_argument("--dossier", help="dossier local de logs CloudTrail (au lieu de S3)")
    p.add_argument("--interface", "-i", default="eth0",
                   help="interface physique recevant le trafic mirroré")
    p.add_argument("--intervalle", type=int, default=INTERVALLE_CLOUDTRAIL)
    p.add_argument("--duree", type=int, default=DUREE_CAPTURE)
    p.add_argument("--une-fois", action="store_true")
    p.add_argument("--verifier", action="store_true")
    args = p.parse_args()

    resoudre_destinations()

    if args.verifier:
        sys.exit(0 if verifier(args.bucket) else 1)

    fils = []
    if args.voie in ("cloudtrail", "deux"):
        if not args.bucket and not args.dossier:
            print("[cloudtrail] ni --bucket ni --dossier : voie ignorée", flush=True)
        else:
            fils.append(threading.Thread(
                target=voie_cloudtrail,
                args=(args.bucket, args.prefixe, args.dossier,
                      args.intervalle, args.une_fois), daemon=True))
    if args.voie in ("mirroring", "deux"):
        fils.append(threading.Thread(
            target=voie_mirroring,
            args=(args.interface, args.duree, args.une_fois), daemon=True))

    if not fils:
        print("Aucune voie activée.", file=sys.stderr)
        sys.exit(1)

    print(f"=== Sonde cloud — {len(fils)} voie(s) active(s) ===", flush=True)
    for f in fils:
        f.start()
    try:
        while any(f.is_alive() for f in fils):
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[sonde] arrêt demandé", flush=True)


if __name__ == "__main__":
    main()
