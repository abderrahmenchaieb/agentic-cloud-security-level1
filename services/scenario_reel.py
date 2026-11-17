"""
=============================================================================
SCÉNARIO RÉALISTE — Sysmon + capture réseau simultanés
=============================================================================
Rejoue une attaque telle qu'elle se présenterait en production : les DEUX
voies décrivent le MÊME incident, sur le même hôte, avec la même IP externe.

    voie 1  journal Sysmon  → Collect → Analysis → Decision
    voie 2  capture réseau  → Anonymization → Decision
                                    ↓
                        Decision corrèle par intersection d'IP
                        → mission GEOLOCATION

CE QUE CE SCÉNARIO REPRODUIT DU RÉEL

  1. Le trafic de fond existe. Une machine réelle génère en permanence des
     flux légitimes (navigation, mises à jour, DNS). L'attaque s'y noie.

  2. Le graphe réseau est DENSE. E-GraphSAGE agrège l'information des
     voisins : sur quelques flux isolés, chaque arête n'a aucun contexte et
     le modèle ne retrouve pas les motifs appris sur 141 530 arêtes. On
     injecte donc un volume réaliste — c'est une contrainte du GNN, pas un
     artifice.

  3. Les deux voies sont SIMULTANÉES et partagent l'IP du C2. C'est ce
     recoupement qui permet au Decision Agent de rapprocher la menace de
     l'anonymisation. Sans lui, il produit deux verdicts sans lien.

  4. L'attaque suit une progression : injection → chargement de DLL →
     exfiltration, dans la même session de processus.

USAGE
    python3 scenario_reel.py                      trafic de fond synthétique
    python3 scenario_reel.py --csv Darknet.csv    trafic de fond réel
    python3 scenario_reel.py --fond 3000          densité du graphe
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

HOTE = "VM-PROD-01"
GUID = "{ATTACK-0001-0002-0003}"
IP_C2 = "185.220.101.5"        # nœud de sortie Tor réel
IP_INTERNE = "192.168.1.47"


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
# VOIE 1 — journal Sysmon
# =============================================================================
def evenements_sysmon(base: datetime) -> list[dict]:
    """
    L'attaque vue depuis le journal système : injection dans lsass, puis
    chargement de DLL réseau, puis connexions sortantes vers le C2.

    Tout sous le MÊME process_guid : c'est ce qui forme une séquence unique,
    et donc ce qui permet à la séquence de porter à la fois la signature
    d'injection et l'IP externe.
    """
    ev, d = [], 0

    def evt(eid, **kw):
        nonlocal d
        e = {"EventID": eid,
             "UtcTime": (base + timedelta(seconds=d)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
             "Computer": HOTE, "ProcessGuid": GUID,
             "Image": r"C:\Windows\System32\svchost.exe"}
        e.update(kw)
        d += 1
        return e

    # bruit de fond : activité normale de la machine
    for i in range(20):
        ev.append(evt(13, TargetObject=rf"HKLM\SOFTWARE\Microsoft\Windows\Cle{i % 6}"))
    for i in range(8):
        ev.append(evt(11, TargetFilename=rf"C:\Users\prod\AppData\Local\Temp\wu{i}.tmp"))

    # 1. injection de code dans lsass (T1055)
    for i in range(7):
        ev.append(evt(8, TargetProcessGuid=f"{{LSASS-{i:04d}}}",
                      TargetImage=r"C:\Windows\System32\lsass.exe",
                      GrantedAccess="0x1F3FFF"))

    # 2. chargement des bibliothèques réseau
    for i, dll in enumerate(("ws2_32.dll", "wininet.dll", "winhttp.dll")):
        ev.append(evt(7, ImageLoaded=rf"C:\Windows\System32\{dll}",
                      Hashes=f"SHA1=NET{i:04d}"))

    # 3. exfiltration vers le C2 — même session
    for i in range(14):
        ev.append(evt(3, SourceIp=IP_INTERNE, DestinationIp=IP_C2,
                      DestinationPort=9001 if i % 3 else 443,
                      Protocol="tcp", Initiated="true"))

    # 4. effacement de traces : trous dans les record-ID
    for i, record in enumerate([4100, 4101, 4102, 9800, 9801]):
        ev.append(evt(13, RecordNumber=str(record),
                      TargetObject=rf"HKLM\SYSTEM\CurrentControlSet\Trace{i}"))

    return ev


# =============================================================================
# VOIE 2 — capture réseau
# =============================================================================
def flux_reseau(n_fond: int, csv: str | None) -> list[dict]:
    """
    Le MÊME incident vu depuis la capture réseau : les flux vers le C2,
    noyés dans le trafic de fond de la machine.

    Le trafic de fond n'est pas décoratif : sans lui, le graphe se réduit à
    quelques arêtes et E-GraphSAGE, qui classe une arête d'après son
    voisinage, n'a aucun contexte pour décider.
    """
    from injecter_flux import (charger_reference, flux_depuis_csv,
                               flux_depuis_distributions)
    colonnes, moyennes, ecarts = charger_reference()

    if csv and os.path.exists(csv):
        fond = flux_depuis_csv(csv, colonnes, n_fond)
    else:
        fond = flux_depuis_distributions(colonnes, moyennes, ecarts, n_fond)
    for f in fond:
        f.pop("_attendu", None)

    # les flux de l'attaque : profil Tor marqué, vers le C2
    import numpy as np
    rng = np.random.default_rng(7)
    idx_temps = [i for i, c in enumerate(colonnes)
                 if any(m in c.lower() for m in ("duration", "iat", "idle"))]

    attaque = []
    for k in range(14):
        v = np.abs(moyennes + rng.normal(0, 0.5, len(moyennes)) * ecarts) * 2.2
        for i in idx_temps:
            v[i] *= 2.8          # trois relais Tor allongent les temps
        attaque.append({
            "flow_id": f"c2-{k}",
            "src_ip": IP_INTERNE,
            "dst_ip": IP_C2,
            "dst_port": 9001 if k % 3 else 443,
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
            print(f"\n    mission   : {m.get('mission', '?').upper()}")
            print(f"    hôte      : {m.get('host')}")
            print(f"    menace    : {d.get('threat_score', 0):.2f}")
            ips = d.get("anonymized_ips") or []
            types = d.get("anonymization_types") or []
            print(f"    IP masquées : {', '.join(map(str, ips)) or '(aucune)'}"
                  f"{'  [' + ', '.join(map(str, types)) + ']' if types else ''}")
            for j in m.get("justificatifs", []):
                print(f"      · {j}")
    else:
        print("\n  aucune escalade — la corrélation n'a pas abouti")

    print(f"\n  Dashboard : {BUS_URL}/")


def main() -> None:
    p = argparse.ArgumentParser(description="Scénario réaliste Sysmon + réseau")
    p.add_argument("--csv", help="CSV brut de CIC-Darknet2020 (trafic de fond réel)")
    p.add_argument("--fond", type=int, default=3000,
                   help="volume du trafic de fond (densité du graphe)")
    args = p.parse_args()

    print("=" * 68)
    print("  SCÉNARIO RÉALISTE — les deux voies, le même incident")
    print("=" * 68)
    if not verifier():
        sys.exit(1)

    base = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=3)

    print(f"\n  Incident simulé sur {HOTE}")
    print(f"    injection lsass → DLL réseau → exfiltration vers {IP_C2} (Tor)")
    print(f"    puis effacement de traces\n")

    # --- voie réseau d'abord : Anonymization doit avoir vu l'IP quand la
    #     menace arrive, pour que Decision puisse corréler
    flux = flux_reseau(args.fond, args.csv)
    print(f"  [voie réseau] {len(flux)} flux "
          f"({args.fond} de fond + 14 vers le C2)")
    r = post(f"{ANON_URL}/ingest", {"flows": flux, "source": "scenario_reel"})
    print(f"    → {r}")

    time.sleep(3)

    # --- voie Sysmon
    ev = evenements_sysmon(base)
    print(f"\n  [voie Sysmon] {len(ev)} événements")
    r = post(f"{COLLECT_URL}/ingest", {"events": ev})
    print(f"    → {r}")

    print()
    attendre_stabilisation()
    rapport()

    print("\n  Ce scénario reproduit les conditions réelles : deux sources")
    print("  simultanées décrivant le même incident, reliées par l'IP du C2.")


if __name__ == "__main__":
    main()
