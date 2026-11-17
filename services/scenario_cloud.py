"""
=============================================================================
SCÉNARIO RÉALISTE — CLOUD (CloudTrail + trafic mirroré)
=============================================================================
Pendant cloud de `scenario_reel.py`. Les DEUX voies décrivent le même
incident AWS, reliées par l'IP de l'attaquant.

    voie 1  CloudTrail (plan de contrôle)  → Collect → Analysis → Decision
    voie 2  trafic mirroré (plan de données) → Anonymization → Decision

⚠️ POURQUOI DEUX SOURCES CÔTÉ CLOUD
    CloudTrail journalise les APPELS D'API : qui a fait quoi, depuis quelle
    IP. Il ne porte AUCUNE statistique de flux — pas de durée, pas de tailles
    de paquets. E-GraphSAGE ne peut donc rien en tirer.

    Le VPC Traffic Mirroring copie le trafic réseau réel. Traité par
    CICFlowMeter, il fournit les 76 features du modèle. C'est ce qui donne au
    cloud la parité avec la voie Windows.

L'ATTAQUE SIMULÉE — compromission d'identité IAM
    1. reconnaissance      ListBuckets, DescribeInstances, GetCallerIdentity
    2. persistance         CreateAccessKey sur un compte de service
    3. escalade            AttachUserPolicy vers AdministratorAccess
    4. exfiltration        GetObject en série sur un bucket sensible
    5. évasion             StopLogging — arrêt de CloudTrail lui-même

    Le tout depuis 185.220.101.5, un nœud de sortie Tor.

USAGE
    python3 scenario_cloud.py                    trafic de fond synthétique
    python3 scenario_cloud.py --csv Darknet.csv  trafic de fond réel
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

IP_ATTAQUANT = "185.220.101.5"      # nœud de sortie Tor réel
COMPTE = "111122223333"
IDENTITE = f"arn:aws:iam::{COMPTE}:user/svc-backup"
REGION = "us-east-1"


def post(url: str, payload: dict, timeout: float = 120.0):
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
# VOIE 1 — CloudTrail
# =============================================================================
def evenements_cloudtrail(base: datetime) -> list[dict]:
    """
    L'incident vu depuis le plan de contrôle AWS. Progression réaliste :
    reconnaissance, persistance, escalade de privilèges, exfiltration, évasion.
    """
    ev, d = [], 0

    def evt(source: str, nom: str, ip: str = IP_ATTAQUANT,
            agent: str = "aws-cli/2.13.0", erreur: str | None = None,
            **params):
        nonlocal d
        e = {
            "eventVersion": "1.08",
            "eventTime": (base + timedelta(seconds=d)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "eventSource": f"{source}.amazonaws.com",
            "eventName": nom,
            "awsRegion": REGION,
            "sourceIPAddress": ip,
            "userAgent": agent,
            "userIdentity": {"type": "IAMUser", "arn": IDENTITE,
                             "principalId": "AIDAEXAMPLE", "accountId": COMPTE,
                             "userName": "svc-backup"},
            "eventType": "AwsApiCall",
            "recipientAccountId": COMPTE,
            "requestParameters": params or None,
        }
        if erreur:
            e["errorCode"] = erreur
        d += 3
        return e

    # --- bruit de fond : activité légitime d'un compte de service ---
    for i in range(12):
        ev.append(evt("s3", "GetObject", ip="10.0.3.14",
                      agent="aws-sdk-java/1.12", bucketName="backups-quotidiens",
                      key=f"db/2026-08-{i+1:02d}.dump"))
    for i in range(5):
        ev.append(evt("cloudwatch", "PutMetricData", ip="10.0.3.14",
                      agent="aws-sdk-java/1.12"))

    # --- 1. RECONNAISSANCE — l'attaquant explore ---
    for nom, src in (("GetCallerIdentity", "sts"), ("ListBuckets", "s3"),
                     ("DescribeInstances", "ec2"), ("ListUsers", "iam"),
                     ("ListRoles", "iam"), ("DescribeDBInstances", "rds")):
        ev.append(evt(src, nom))
    # quelques refus : signature classique d'une exploration à l'aveugle
    for nom, src in (("ListSecrets", "secretsmanager"), ("DescribeKey", "kms")):
        ev.append(evt(src, nom, erreur="AccessDenied"))

    # --- 2. PERSISTANCE — nouvelle clé d'accès ---
    ev.append(evt("iam", "CreateAccessKey", userName="svc-backup"))
    ev.append(evt("iam", "CreateUser", userName="svc-monitor"))

    # --- 3. ESCALADE DE PRIVILÈGES ---
    ev.append(evt("iam", "AttachUserPolicy", userName="svc-monitor",
                  policyArn="arn:aws:iam::aws:policy/AdministratorAccess"))

    # --- 4. EXFILTRATION — lecture en série d'un bucket sensible ---
    for i in range(15):
        ev.append(evt("s3", "GetObject", bucketName="donnees-clients-prod",
                      key=f"exports/clients-{i:03d}.csv"))

    # --- 5. ÉVASION — arrêt de la journalisation ---
    ev.append(evt("cloudtrail", "StopLogging",
                  name=f"arn:aws:cloudtrail:{REGION}:{COMPTE}:trail/audit-principal"))
    ev.append(evt("cloudtrail", "DeleteTrail",
                  name=f"arn:aws:cloudtrail:{REGION}:{COMPTE}:trail/audit-secondaire"))

    return ev


# =============================================================================
# VOIE 2 — trafic mirroré
# =============================================================================
def flux_mirrores(n_fond: int, csv: str | None) -> list[dict]:
    """
    Le même incident vu depuis le VPC Traffic Mirroring : les connexions de
    l'attaquant, noyées dans le trafic du VPC.

    Le volume de fond est nécessaire : E-GraphSAGE classe une arête d'après
    son voisinage. Sur quelques flux isolés, il n'a aucun contexte.
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

    rng = np.random.default_rng(11)
    idx_temps = [i for i, c in enumerate(colonnes)
                 if any(m in c.lower() for m in ("duration", "iat", "idle"))]

    attaque = []
    for k in range(18):
        v = np.abs(moyennes + rng.normal(0, 0.5, len(moyennes)) * ecarts) * 2.2
        for i in idx_temps:
            v[i] *= 2.8          # trois relais Tor allongent les temps
        attaque.append({
            "flow_id": f"vpc-{k}",
            "src_ip": IP_ATTAQUANT,          # l'attaquant vers l'API AWS
            "dst_ip": "52.94.236.248",       # point de terminaison AWS
            "dst_port": 443,
            "protocol": "TCP",
            "features": {c: float(x) for c, x in zip(colonnes, v)},
        })
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
            elif nom == "collect":
                extra = f"  modèles={etat.get('models')}"
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
    print("\n" + "=" * 68)
    print("  RÉSULTAT")
    print("=" * 68)
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

    etat = get(f"{BUS_URL}/state", timeout=20) or {}
    positions = etat.get("positions", {})
    masquees = sum(1 for p in (positions.values() if isinstance(positions, dict)
                               else positions)
                   if not p.get("position_is_real", True))
    print(f"\n  dashboard : {len(etat.get('hosts', {}))} hôte(s), "
          f"{len(etat.get('attacks', {}))} attaque(s), "
          f"{len(positions)} position(s) dont {masquees} masquée(s), "
          f"{len(etat.get('cooperation', []))} échange(s)")

    msgs = (get(f"{DECISION_URL}/niveau2", timeout=20) or {}).get("messages", [])
    if msgs:
        print(f"\n  ESCALADES VERS LE NIVEAU 2 ({len(msgs)})")
        for m in msgs[-4:]:
            d = m.get("donnees", {})
            print(f"\n    mission     : {m.get('mission', '?').upper()}")
            print(f"    entité      : {m.get('host') or m.get('entity_key')}")
            print(f"    menace      : {d.get('threat_score', 0):.2f}")
            print(f"    IP masquées : "
                  f"{', '.join(map(str, d.get('anonymized_ips') or [])) or '(aucune)'}")
            for j in m.get("justificatifs", []):
                print(f"      · {j}")
    else:
        print("\n  aucune escalade — la corrélation n'a pas abouti")
    print(f"\n  Dashboard : {BUS_URL}/")


def main() -> None:
    p = argparse.ArgumentParser(description="Scénario réaliste cloud")
    p.add_argument("--csv", help="CSV brut de CIC-Darknet2020 (trafic de fond)")
    p.add_argument("--fond", type=int, default=3000)
    args = p.parse_args()

    print("=" * 68)
    print("  SCÉNARIO RÉALISTE — CLOUD (CloudTrail + trafic mirroré)")
    print("=" * 68)
    if not verifier():
        sys.exit(1)

    base = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=5)
    print(f"\n  Incident simulé sur le compte AWS {COMPTE}")
    print(f"    identité compromise : svc-backup")
    print(f"    reconnaissance → CreateAccessKey → AdministratorAccess")
    print(f"    → exfiltration S3 → StopLogging")
    print(f"    depuis {IP_ATTAQUANT} (Tor)\n")

    # voie réseau d'abord : Anonymization doit connaître l'IP quand la menace arrive
    flux = flux_mirrores(args.fond, args.csv)
    print(f"  [trafic mirroré] {len(flux)} flux ({args.fond} de fond + 18 attaquant)")
    print(f"    → {post(f'{ANON_URL}/ingest', {'flows': flux, 'source': 'scenario_cloud'})}")

    time.sleep(3)

    ev = evenements_cloudtrail(base)
    print(f"\n  [CloudTrail] {len(ev)} événements")
    print(f"    → {post(f'{COLLECT_URL}/ingest', {'events': ev, 'source': 'cloudtrail'})}")

    print()
    attendre_stabilisation()
    rapport()

    print("\n  Les deux plans AWS — contrôle (CloudTrail) et données (mirroring)")
    print("  — décrivent le même incident, reliés par l'IP de l'attaquant.")


if __name__ == "__main__":
    main()
