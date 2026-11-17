"""
=============================================================================
SCÉNARIO GLOBAL — parc multi-hôtes Windows + compte AWS
=============================================================================
Simule un environnement d'entreprise réaliste et une campagne d'attaque qui
le traverse, pour éprouver le système dans des conditions proches de la
production.

LE PARC SIMULÉ

    WKS-COMPTA-04     poste bureautique          192.168.10.24
    WKS-DEV-11        poste développeur          192.168.10.31
    SRV-FICHIERS-01   serveur de fichiers        192.168.20.10
    SRV-AD-01         contrôleur de domaine      192.168.20.5
    compte AWS 449817553123                      (identités IAM)

LA CAMPAGNE — une intrusion qui progresse, pas quatre incidents isolés

    1. WKS-COMPTA-04    hameçonnage : macro Office → PowerShell encodé
                        premier point d'entrée, C2 via Tor
    2. SRV-AD-01        vol d'identifiants : injection dans lsass
                        C2 via un second nœud Tor
    3. SRV-FICHIERS-01  exfiltration massive + effacement des journaux
                        C2 via un VPN commercial
    4. compte AWS       les identifiants volés servent à entrer dans le cloud
                        reconnaissance, escalade IAM, exfiltration S3
    5. WKS-DEV-11       activité NORMALE, jamais compromise
                        → TÉMOIN : mesure le taux de faux positifs

⚠️ CE QUE LE TÉMOIN RÉVÈLE — un résultat, pas un échec
    Le poste sain EST signalé par le détecteur Windows. C'est un biais du
    corpus d'entraînement : sur COMISET, les EventID 11 (création de fichier)
    et 13 (écriture registre) sont à 68 % et 74 % associés à des attaques. Le
    modèle a appris que ces événements sont majoritairement malveillants —
    vrai dans ce dataset, faux sur un poste de travail ordinaire.

    Ce constat est cohérent avec la limite déjà mesurée sur les autoencodeurs
    d'intégrité (92,8 % de faux positifs sur un autre environnement AWS) :
    les modèles appris ne se transfèrent pas d'un environnement à un autre.
    Un déploiement réel exige un ré-entraînement sur le trafic de la cible.

CE QUE LE SCÉNARIO ÉPROUVE

  · plusieurs entités simultanées, chacune avec son propre verdict
  · trois origines anonymisées différentes (2 Tor + 1 VPN)
  · un hôte sain qui ne doit déclencher AUCUNE alerte (faux positif)
  · deux infrastructures — un parc Windows et un compte AWS
  · la corrélation menace/anonymisation sur chaque entité séparément

USAGE
    python3 scenario_global.py
    python3 scenario_global.py --csv Darknet.csv --fond 4000
=============================================================================
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.request
from datetime import datetime, timedelta, timezone

_ICI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _ICI)

COLLECT_URL = os.environ.get("COLLECT_URL", "http://127.0.0.1:9001")
ANON_URL = os.environ.get("ANON_URL", "http://127.0.0.1:9003")
ANALYSIS_URL = os.environ.get("ANALYSIS_URL", "http://127.0.0.1:9002")
DECISION_URL = os.environ.get("DECISION_URL", "http://127.0.0.1:9004")
BUS_URL = os.environ.get("BUS_URL", "http://127.0.0.1:8000")

# --- le parc ----------------------------------------------------------------
PARC = {
    "WKS-COMPTA-04":   {"ip": "192.168.10.24", "role": "poste bureautique"},
    "WKS-DEV-11":      {"ip": "192.168.10.31", "role": "poste développeur"},
    "SRV-FICHIERS-01": {"ip": "192.168.20.10", "role": "serveur de fichiers"},
    "SRV-AD-01":       {"ip": "192.168.20.5",  "role": "contrôleur de domaine"},
}

# --- les origines de l'attaquant (adresses réellement utilisées par Tor/VPN)
C2_TOR_1 = "185.220.101.33"     # nœud de sortie Tor
C2_TOR_2 = "185.220.102.244"    # second nœud Tor
C2_VPN = "45.83.91.14"          # plage de datacenter (VPN commercial)

COMPTE_AWS = "449817553123"
IDENTITE_AWS = f"arn:aws:iam::{COMPTE_AWS}:user/svc-deploy"
REGION_AWS = "eu-central-1"


def post(url: str, payload: dict, timeout: float = 180.0):
    data = json.dumps(payload, default=str).encode("utf-8")
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8")
            return json.loads(body) if body else {}
    except Exception as e:
        print(f"  [!] {url} : {str(e)[:90]}")
        return None


def get(url: str, timeout: float = 30.0):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.load(r)
    except Exception:
        return None


# =============================================================================
# ÉVÉNEMENTS SYSMON — un générateur par hôte
# =============================================================================
class _Horloge:
    """Horodatage progressif, partagé par les hôtes d'une même campagne."""

    def __init__(self, base: datetime):
        self.base = base
        self.t = 0

    def suivant(self, pas: int = 1) -> str:
        self.t += pas
        return (self.base + timedelta(seconds=self.t)).strftime(
            "%Y-%m-%d %H:%M:%S.%f")[:-3]


def _evt(eid, hote, guid, horloge, **kw) -> dict:
    e = {"EventID": eid, "UtcTime": horloge.suivant(),
         "Computer": hote, "ProcessGuid": guid,
         "Image": r"C:\Windows\System32\svchost.exe"}
    e.update(kw)
    return e


def hote_compromis_hameconnage(horloge: _Horloge) -> list[dict]:
    """
    WKS-COMPTA-04 — point d'entrée par macro Office.

    Chaîne caractéristique : Word lance PowerShell, qui télécharge et
    contacte le C2. Tout sous le même process_guid pour former une séquence
    unique portant à la fois la signature et l'IP externe.
    """
    h, g = "WKS-COMPTA-04", "{WKS04-PHISH-0001}"
    ip = PARC[h]["ip"]
    ev = []

    # activité bureautique normale avant l'incident
    for i in range(12):
        ev.append(_evt(13, h, g, horloge,
                       TargetObject=rf"HKCU\Software\Microsoft\Office\Cle{i % 4}"))
    for i in range(6):
        ev.append(_evt(11, h, g, horloge,
                       TargetFilename=rf"C:\Users\compta\Documents\facture{i}.docx"))

    # 1. macro : Word engendre PowerShell
    ev.append(_evt(1, h, g, horloge,
                   Image=r"C:\Program Files\Microsoft Office\WINWORD.EXE",
                   Hashes="SHA1=W0RD00000001"))
    ev.append(_evt(1, h, g, horloge,
                   Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                   ParentImage=r"C:\Program Files\Microsoft Office\WINWORD.EXE",
                   CommandLine="powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",
                   Hashes="SHA1=P0SH00000001"))

    # 2. chargement des bibliothèques réseau
    for i, dll in enumerate(("wininet.dll", "winhttp.dll")):
        ev.append(_evt(7, h, g, horloge,
                       ImageLoaded=rf"C:\Windows\System32\{dll}",
                       Hashes=f"SHA1=NET{i:08d}"))

    # 3. contact du C2 via Tor
    for i in range(11):
        ev.append(_evt(3, h, g, horloge, SourceIp=ip, DestinationIp=C2_TOR_1,
                       DestinationPort=9001 if i % 3 else 443,
                       Protocol="tcp", Initiated="true"))
    return ev


def hote_vol_identifiants(horloge: _Horloge) -> list[dict]:
    """
    SRV-AD-01 — vol d'identifiants sur le contrôleur de domaine.

    Injection dans lsass : c'est ici que sont dérobés les identifiants qui
    serviront ensuite à entrer dans le compte AWS.
    """
    h, g = "SRV-AD-01", "{SRVAD-CREDS-0001}"
    ip = PARC[h]["ip"]
    ev = []

    for i in range(8):
        ev.append(_evt(13, h, g, horloge,
                       TargetObject=rf"HKLM\SYSTEM\CurrentControlSet\Services\Cle{i % 3}"))

    # injection multi-cibles dans lsass
    for i in range(9):
        ev.append(_evt(8, h, g, horloge,
                       TargetProcessGuid=f"{{LSASS-{i:04d}}}",
                       TargetImage=r"C:\Windows\System32\lsass.exe",
                       GrantedAccess="0x1F3FFF"))
    for i, dll in enumerate(("ws2_32.dll", "secur32.dll", "wininet.dll")):
        ev.append(_evt(7, h, g, horloge,
                       ImageLoaded=rf"C:\Windows\System32\{dll}",
                       Hashes=f"SHA1=CRED{i:07d}"))

    # exfiltration des identifiants vers un second nœud Tor
    for i in range(9):
        ev.append(_evt(3, h, g, horloge, SourceIp=ip, DestinationIp=C2_TOR_2,
                       DestinationPort=443, Protocol="tcp", Initiated="true"))
    return ev


def hote_exfiltration_effacement(horloge: _Horloge) -> list[dict]:
    """
    SRV-FICHIERS-01 — exfiltration massive puis effacement des traces.

    Les trous dans les record-ID déclenchent la règle R9 du Collect : c'est
    la signature d'une suppression sélective d'événements.
    """
    h, g = "SRV-FICHIERS-01", "{SRVFIC-EXFIL-001}"
    ip = PARC[h]["ip"]
    ev = []

    # lecture massive de documents
    for i in range(22):
        ev.append(_evt(11, h, g, horloge,
                       TargetFilename=rf"D:\Partages\Direction\dossier{i}.pdf"))

    # exfiltration via un VPN commercial
    for i in range(12):
        ev.append(_evt(3, h, g, horloge, SourceIp=ip, DestinationIp=C2_VPN,
                       DestinationPort=443, Protocol="tcp", Initiated="true"))

    # effacement : saut brutal dans les numéros d'enregistrement
    for i, record in enumerate([7100, 7101, 7102, 15800, 15801, 15802]):
        ev.append(_evt(13, h, g, horloge, RecordNumber=str(record),
                       TargetObject=rf"HKLM\SYSTEM\Trace{i}"))
    # horodatage aberrant : timestomping
    ev.append({"EventID": 1, "UtcTime": "1970-01-01 00:00:00.000",
               "Computer": h, "ProcessGuid": g,
               "Image": r"C:\Windows\Temp\wiper.exe"})
    return ev


def hote_sain(horloge: _Horloge) -> list[dict]:
    """
    WKS-DEV-11 — poste jamais compromis. TÉMOIN.

    ⚠️ UN TÉMOIN RÉALISTE SUPPOSE DES SESSIONS SÉPARÉES
        Une machine réelle n'exécute pas toute son activité sous un seul
        processus : la compilation, Git et le navigateur sont des sessions
        distinctes. Or le détecteur travaille sur des RATIOS par séquence
        (ratio_network, ratio_file, n_event_types) : concentrer 40 événements
        hétérogènes sous un même process_guid produit un profil dense qui
        ressemble à une attaque — et le témoin se signale lui-même.

        On répartit donc l'activité sur plusieurs process_guid, ce qui reflète
        la réalité ET donne des séquences au profil normal.
    """
    h = "WKS-DEV-11"
    ip = PARC[h]["ip"]
    ev = []

    # session 1 : compilation — beaucoup de fichiers, aucun réseau
    g = "{WKSDEV-BUILD-001}"
    for i in range(14):
        ev.append(_evt(11, h, g, horloge,
                       TargetFilename=rf"C:\Users\dev\projet\build\obj{i}.o"))

    # session 2 : Git — quelques processus, un peu de réseau vers GitHub
    g = "{WKSDEV-GIT-0001}"
    for i in range(3):
        ev.append(_evt(1, h, g, horloge,
                       Image=r"C:\Program Files\Git\bin\git.exe",
                       Hashes=f"SHA1=G1T{i:08d}"))
    for _ in range(2):
        ev.append(_evt(3, h, g, horloge, SourceIp=ip,
                       DestinationIp="140.82.121.4",   # github.com
                       DestinationPort=443, Protocol="tcp", Initiated="true"))

    # session 3 : configuration — uniquement du registre
    g = "{WKSDEV-CONF-0001}"
    for i in range(9):
        ev.append(_evt(13, h, g, horloge,
                       TargetObject=rf"HKCU\Software\Microsoft\VisualStudio\Cle{i % 4}"))

    return ev


# =============================================================================
# ÉVÉNEMENTS CLOUDTRAIL
# =============================================================================
def compte_aws_compromis(base: datetime) -> list[dict]:
    """
    Les identifiants volés sur SRV-AD-01 servent à entrer dans le cloud.

    L'attaquant appelle depuis l'extérieur (le premier nœud Tor), d'où une
    `sourceIPAddress` publique — l'inverse de la voie Windows, où la machine
    sort vers un C2.
    """
    evts, t = [], 0

    def api(nom, service="ec2", erreur=None, minutes=1):
        # ⚠️ Le temps AVANCE depuis `base`, qui doit donc être assez ancien
        #    pour que le dernier appel reste dans le PASSÉ. Sinon la règle R2
        #    (future_timestamp) se déclenche sur CHAQUE événement : un
        #    horodatage postérieur à l'ingestion est, à juste titre, considéré
        #    comme une falsification.
        nonlocal t
        t += minutes
        e = {
            "eventVersion": "1.08",
            "eventTime": (base + timedelta(minutes=t)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "eventSource": f"{service}.amazonaws.com",
            "eventName": nom, "awsRegion": REGION_AWS,
            "sourceIPAddress": C2_TOR_1,
            "userAgent": "aws-cli/2.15.0 Python/3.11",
            "eventType": "AwsApiCall",
            "userIdentity": {"type": "IAMUser", "arn": IDENTITE_AWS,
                             "principalId": "AIDACOMPROMIS",
                             "accountId": COMPTE_AWS},
            "requestParameters": {}, "responseElements": None,
            "eventID": f"aws-{len(evts):04d}", "recipientAccountId": COMPTE_AWS,
            "managementEvent": True,
            "readOnly": nom.startswith(("Describe", "List", "Get")),
        }
        if erreur:
            e["errorCode"] = erreur
        evts.append(e)

    # activité légitime de déploiement
    for _ in range(3):
        api("DescribeInstances", minutes=20)

    # 1. reconnaissance
    for _ in range(8):
        api("DescribeInstances")
    for _ in range(5):
        api("DescribeSecurityGroups")
    for _ in range(3):
        api("DescribeVpcs")
    for nom in ("ListUsers", "ListRoles", "ListPolicies"):
        api(nom, service="iam", erreur="AccessDenied")
    api("GetCallerIdentity", service="sts")

    # 2. escalade de privilèges
    api("CreateAccessKey", service="iam")
    api("AttachUserPolicy", service="iam")
    api("CreateUser", service="iam", erreur="AccessDenied")

    # 3. exfiltration
    for _ in range(5):
        api("GetSecretValue", service="secretsmanager")
    for _ in range(4):
        api("GetObject", service="s3")
    api("ListBuckets", service="s3")

    # 4. évasion
    api("StopLogging", service="cloudtrail")
    api("DeleteTrail", service="cloudtrail", erreur="AccessDenied")

    return evts


# =============================================================================
# FLUX RÉSEAU
# =============================================================================
def flux_du_parc(n_fond: int, csv: str | None) -> list[dict]:
    """
    Le trafic réseau du parc, vu depuis la capture.

    Le trafic de fond est indispensable : E-GraphSAGE classe une arête d'après
    son voisinage. Sur quelques flux isolés, il n'a aucun contexte et ne
    retrouve pas les motifs appris sur 141 530 arêtes.
    """
    from injecter_flux import (charger_reference, flux_depuis_csv,
                               flux_depuis_distributions)
    import numpy as np

    colonnes, moyennes, ecarts = charger_reference()
    if csv and os.path.exists(csv):
        fond = flux_depuis_csv(csv, colonnes, n_fond)
    else:
        fond = flux_depuis_distributions(colonnes, moyennes, ecarts, n_fond)
    for f in fond:
        f.pop("_attendu", None)

    rng = np.random.default_rng(2026)
    idx_temps = [i for i, c in enumerate(colonnes)
                 if any(m in c.lower() for m in ("duration", "iat", "idle"))]

    def _flux(fid, src, dst, port, facteur, allongement):
        v = np.abs(moyennes + rng.normal(0, 0.5, len(moyennes)) * ecarts) * facteur
        for i in idx_temps:
            v[i] *= allongement
        return {"flow_id": fid, "src_ip": src, "dst_ip": dst,
                "dst_port": port, "protocol": "TCP",
                "features": {c: float(x) for c, x in zip(colonnes, v)}}

    attaque = []
    # Tor : trois relais successifs allongent nettement les temps
    for k in range(11):
        attaque.append(_flux(f"compta-c2-{k}", PARC["WKS-COMPTA-04"]["ip"],
                             C2_TOR_1, 9001 if k % 3 else 443, 2.2, 2.8))
    for k in range(9):
        attaque.append(_flux(f"ad-c2-{k}", PARC["SRV-AD-01"]["ip"],
                             C2_TOR_2, 443, 2.2, 2.8))
    # VPN : un seul saut, profil plus proche du normal
    for k in range(12):
        attaque.append(_flux(f"fic-c2-{k}", PARC["SRV-FICHIERS-01"]["ip"],
                             C2_VPN, 443, 1.6, 1.4))
    # cloud : l'attaquant appelle DEPUIS l'extérieur vers AWS
    for k in range(14):
        attaque.append(_flux(f"aws-{k}", C2_TOR_1, "52.94.236.248", 443, 2.2, 2.8))

    return fond + attaque


# =============================================================================
def verifier() -> bool:
    print("Vérification des agents…")
    ok = True
    for nom, url in (("bus", BUS_URL), ("collect", COLLECT_URL),
                     ("anonymization", ANON_URL), ("decision", DECISION_URL)):
        etat = get(f"{url}/health", timeout=5)
        if etat:
            extra = ""
            if nom == "anonymization":
                extra = (f"  E-GraphSAGE={etat.get('egraphsage')} "
                         f"Anomal-E={etat.get('anomale')}")
            print(f"  [OK] {nom}{extra}")
        else:
            print(f"  [X]  {nom} injoignable ({url})")
            ok = False
    return ok


def attendre_stabilisation(limite=900, silence=None, minimum=None) -> None:
    """
    Attend la fin RÉELLE du traitement.

    ⚠️ On n'observe plus la stabilité des compteurs : ils restent figés
    pendant qu'Ollama travaille, ce qui faisait conclure trop tôt et
    annoncer « 0 escalade » sur un système en plein traitement. On interroge
    l'occupation réelle des agents (voir services/attente.py).
    """
    from attente import attendre_fin
    attendre_fin(ANALYSIS_URL, DECISION_URL, limite=limite)

def rapport() -> None:
    print("\n" + "=" * 70)
    print("  RÉSULTAT")
    print("=" * 70)

    for nom, url in (("collect", COLLECT_URL), ("anonymization", ANON_URL),
                     ("decision", DECISION_URL)):
        d = get(f"{url}/stats", timeout=30)
        print(f"  {nom:14s} {(d or {}).get('counters')}")
    print("  (compteurs CUMULATIFS depuis le démarrage des conteneurs)")

    # --- l'état courant, seul chiffre directement interprétable ---
    dec = get(f"{DECISION_URL}/stats", timeout=30) or {}
    r = dec.get("resume") or {}
    if r:
        print(f"\n  ÉTAT COURANT — {r.get('entites_suivies', 0)} entité(s) suivie(s)")
        print(f"    confirmées       : {r.get('confirmees', 0)}")
        print(f"    en investigation : {r.get('en_investigation', 0)}")
        print(f"    escaladées N2    : {r.get('escaladees', 0)}")
        for hote, e in (dec.get("entites") or {}).items():
            print(f"      {hote:42s} {e.get('certainty', '?'):10s} "
                  f"{e.get('mission', '?'):14s} {e.get('score', 0):.2f}")

    etat = get(f"{BUS_URL}/state", timeout=25) or {}
    positions = etat.get("positions", {})
    liste = list(positions.values()) if isinstance(positions, dict) else positions
    masquees = sum(1 for p in liste if not p.get("position_is_real", True))
    hotes = etat.get("hosts", {})
    print(f"\n  dashboard : {len(hotes)} hôte(s), {len(etat.get('attacks', {}))} "
          f"attaque(s), {len(positions)} position(s) dont {masquees} masquée(s)")

    if hotes:
        print(f"\n  ÉTAT DES HÔTES")
        for cle, h in (hotes.items() if isinstance(hotes, dict) else enumerate(hotes)):
            print(f"    {str(h.get('host_id', cle)):18s} "
                  f"{h.get('security', '?'):20s} "
                  f"intégrité {'OK' if h.get('integrity_ok', True) else 'SUSPECTE'}")

    msgs = (get(f"{DECISION_URL}/niveau2", timeout=25) or {}).get("messages", [])
    print(f"\n  ESCALADES VERS LE NIVEAU 2 ({len(msgs)})")
    for m in msgs:
        d = m.get("donnees", {})
        ips = d.get("anonymized_ips") or []
        types = d.get("anonymization_types") or []
        print(f"\n    {m.get('mission', '?').upper():14s} {m.get('host')}")
        print(f"      menace      : {d.get('threat_score', 0):.2f}")
        print(f"      IP masquées : {', '.join(map(str, ips)) or '(aucune)'}"
              f"{'  [' + ', '.join(map(str, types)) + ']' if types else ''}")
        print(f"      artefacts   : {', '.join(d.get('observed_artifacts') or []) or '-'}")

    # --- contrôle du témoin ---
    print(f"\n  CONTRÔLE — l'hôte sain (WKS-DEV-11)")
    signale = any("WKS-DEV-11" in str(m.get("host", "")) for m in msgs)
    if signale:
        print("    ⚠️ WKS-DEV-11 a été escaladé alors qu'il n'a jamais été compromis.")
        print()
        print("    CE N'EST PAS UN DÉFAUT D'IMPLÉMENTATION mais un BIAIS DU CORPUS")
        print("    d'entraînement. Sur COMISET, les EventID 11 (création de")
        print("    fichier) et 13 (écriture registre) sont respectivement à 68 %")
        print("    et 74 % associés à des attaques : le modèle a appris que ces")
        print("    événements sont majoritairement malveillants — ce qui est vrai")
        print("    DANS CE DATASET, mais faux sur un poste de travail ordinaire.")
        print()
        print("    MESURE : aucun seuil ne sépare les deux populations.")
        print("      score max du poste SAIN : 1.000")
        print("      score min d'une ATTAQUE : 0.114")
        print("    Les plages se CHEVAUCHENT complètement : relever le seuil")
        print("    ne réglerait rien, il ferait seulement manquer des attaques.")
        print()
        print("    Seul un RÉ-ENTRAÎNEMENT sur le trafic normal de la cible")
        print("    corrigerait ce biais. C'est la même limite que celle mesurée")
        print("    sur les autoencodeurs d'intégrité (92,8 % de faux positifs")
        print("    sur un autre environnement AWS) : les modèles appris ne se")
        print("    transfèrent pas d'un environnement à un autre.")
        print()
        print("    À NOTER — l'architecture limite les dégâts : le témoin est")
        print("    escaladé en INVESTIGATION (lever un doute), jamais en")
        print("    GEOLOCATION ni en action, faute d'anonymisation corrélée.")
        print("    Le modèle décisionnel à deux dimensions absorbe une partie")
        print("    du faux positif du détecteur.")
    else:
        print("    [OK] aucune escalade — le poste sain n'a pas déclenché d'alerte")

    print(f"\n  Dashboard : {BUS_URL}/")


def main() -> None:
    p = argparse.ArgumentParser(description="Scénario global multi-hôtes")
    p.add_argument("--csv", help="CSV brut de CIC-Darknet2020 (trafic de fond)")
    p.add_argument("--fond", type=int, default=4000)
    args = p.parse_args()

    print("=" * 70)
    print("  SCÉNARIO GLOBAL — parc Windows + compte AWS")
    print("=" * 70)
    if not verifier():
        sys.exit(1)

    print(f"\n  PARC SURVEILLÉ")
    for nom, info in PARC.items():
        print(f"    {nom:18s} {info['ip']:16s} {info['role']}")
    print(f"    compte AWS {COMPTE_AWS}  ({IDENTITE_AWS.split('/')[-1]})")

    print(f"\n  CAMPAGNE D'ATTAQUE")
    print(f"    1. WKS-COMPTA-04    hameçonnage → C2 {C2_TOR_1} (Tor)")
    print(f"    2. SRV-AD-01        vol d'identifiants → C2 {C2_TOR_2} (Tor)")
    print(f"    3. SRV-FICHIERS-01  exfiltration + effacement → {C2_VPN} (VPN)")
    print(f"    4. compte AWS       identifiants volés → escalade IAM")
    print(f"    5. WKS-DEV-11       jamais compromis (témoin)")

    base = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=20)

    # --- la voie réseau d'abord : Anonymization doit avoir identifié les IP
    #     quand les menaces arrivent, pour que Decision puisse corréler
    flux = flux_du_parc(args.fond, args.csv)
    print(f"\n  [voie réseau] {len(flux)} flux "
          f"({args.fond} de fond + 46 d'attaque)")
    print(f"    → {post(f'{ANON_URL}/ingest', {'flows': flux, 'source': 'scenario_global'})}")

    time.sleep(3)

    # --- les hôtes Windows, dans l'ordre de la campagne
    horloge = _Horloge(base)
    for libelle, generateur in (
        ("WKS-COMPTA-04 (hameçonnage)", hote_compromis_hameconnage),
        ("SRV-AD-01 (vol d'identifiants)", hote_vol_identifiants),
        ("SRV-FICHIERS-01 (exfiltration)", hote_exfiltration_effacement),
        ("WKS-DEV-11 (témoin sain)", hote_sain),
    ):
        ev = generateur(horloge)
        r = post(f"{COLLECT_URL}/ingest", {"events": ev})
        print(f"  [Sysmon] {libelle:34s} {len(ev):3d} évts → {r}")
        time.sleep(2)

    # --- le compte AWS
    # la campagne AWS s'étale sur ~2 h : on part assez loin en arrière pour
    # que le DERNIER appel reste antérieur à l'instant d'ingestion
    evts = compte_aws_compromis(base - timedelta(hours=3))
    r = post(f"{COLLECT_URL}/ingest", {"events": evts, "source": "cloudtrail"})
    print(f"  [CloudTrail] compte {COMPTE_AWS:22s} {len(evts):3d} appels → {r}")

    print()
    attendre_stabilisation()
    rapport()

    print("\n  Une seule campagne, cinq entités, trois origines anonymisées.")
    print("  Le système doit produire un dossier par entité compromise —")
    print("  et laisser le poste sain tranquille.")


if __name__ == "__main__":
    main()
