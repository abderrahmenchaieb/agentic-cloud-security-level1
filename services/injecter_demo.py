"""
=============================================================================
INJECTEUR DE DÉMONSTRATION — tester le système sans VM
=============================================================================
Simule une sonde Windows en envoyant des événements Sysmon réalistes au
système. Permet de valider toute la chaîne — Collect → Analysis → Decision →
dashboard — sur une seule machine, avant d'ajouter la VM.

CE QU'IL INJECTE
    1. activité BÉNIGNE      — bruit de fond normal (registre, fichiers)
    2. injection de code     — CreateRemoteThread vers lsass (T1055)
    3. communication C2      — connexions vers une IP Tor connue
    4. reconnaissance        — chargements de DLL, création de processus
    5. falsification de logs — trous de record-ID, horodatages incohérents

Chaque scénario est envoyé séparément, avec une pause, pour qu'on voie le
dashboard réagir en direct plutôt que d'assister à un unique bloc.

USAGE
    python3 injecter_demo.py                  scénario complet
    python3 injecter_demo.py --scenario 2     un seul scénario
    python3 injecter_demo.py --boucle         en continu (démonstration)
    python3 injecter_demo.py --benin          bruit de fond seul
=============================================================================
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import time
import urllib.request
from datetime import datetime, timedelta, timezone

COLLECT_URL = "http://127.0.0.1:9001"
ANALYSIS_URL = "http://127.0.0.1:9002"
DECISION_URL = "http://127.0.0.1:9004"
BUS_URL = "http://127.0.0.1:8000"

HOTE = "VM-DEMO"
GUID = "{DEMO-0001-0002-0003}"
IP_TOR = "185.220.101.5"      # plage réellement utilisée par des nœuds Tor


def post(url: str, payload: dict, timeout: float = 60.0):
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


def _horodatage(base: datetime, decalage: int) -> str:
    return (base + timedelta(seconds=decalage)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def _evenement(eid: int, base: datetime, decalage: int, **extra) -> dict:
    d = {"EventID": eid, "UtcTime": _horodatage(base, decalage),
         "Computer": HOTE, "ProcessGuid": GUID,
         "Image": r"C:\Windows\System32\svchost.exe"}
    d.update(extra)
    return d


# -----------------------------------------------------------------------------
# SCÉNARIOS
# -----------------------------------------------------------------------------
def scenario_benin(base: datetime) -> list[dict]:
    """Bruit de fond : registre et fichiers, l'activité la plus courante."""
    ev = []
    for i in range(25):
        ev.append(_evenement(13, base, i,
                             TargetObject=rf"HKLM\SOFTWARE\Microsoft\Cle{i % 5}"))
    for i in range(10):
        ev.append(_evenement(11, base, 25 + i,
                             TargetFilename=rf"C:\Users\demo\AppData\tmp{i}.dat"))
    return ev


def scenario_injection(base: datetime) -> list[dict]:
    """T1055 — injection de code : CreateRemoteThread vers plusieurs cibles."""
    return [_evenement(8, base, i,
                       TargetProcessGuid=f"{{CIBLE-{i:04d}}}",
                       TargetImage=r"C:\Windows\System32\lsass.exe",
                       GrantedAccess="0x1F3FFF")
            for i in range(8)]


def scenario_c2(base: datetime) -> list[dict]:
    """Communication vers un serveur de commande via une IP Tor."""
    ev = []
    for i in range(12):
        ev.append(_evenement(3, base, i * 3,
                             DestinationIp=IP_TOR,
                             DestinationPort=9001 if i % 2 else 443,
                             Protocol="tcp",
                             Initiated="true"))
    return ev


def scenario_reconnaissance(base: datetime) -> list[dict]:
    """Chargements de DLL et créations de processus — phase de découverte."""
    ev = []
    for i in range(6):
        ev.append(_evenement(7, base, i,
                             ImageLoaded=rf"C:\Windows\System32\dll{i}.dll",
                             Hashes=f"SHA1=AAAA{i:04d}"))
    for i, outil in enumerate(("whoami.exe", "net.exe", "ipconfig.exe",
                               "systeminfo.exe")):
        ev.append(_evenement(1, base, 10 + i,
                             Image=rf"C:\Windows\System32\{outil}",
                             Hashes=f"SHA1=BBBB{i:04d}",
                             ParentImage=r"C:\Windows\System32\cmd.exe"))
    return ev


def scenario_attaque_complete(base: datetime) -> list[dict]:
    """
    Attaque réaliste : injection PUIS communication C2, dans la MÊME session
    de processus.

    ⚠️ POURQUOI C'EST DÉTERMINANT
        Le corrélateur du Decision Agent rapproche menace et anonymisation par
        INTERSECTION D'IP. Si l'injection et le trafic C2 sont émis sous des
        process_guid différents, ils forment deux séquences distinctes : celle
        qui déclenche l'alerte n'a pas d'IP, celle qui a l'IP ne déclenche pas
        d'alerte. Le rapprochement devient impossible et la mission reste
        « investigation » au lieu de « geolocation ».

        Une vraie attaque enchaîne ces actions dans la même session — c'est
        précisément ce qui permet la corrélation.
    """
    ev = []
    d = 0
    # 1. injection de code dans lsass
    for i in range(6):
        ev.append(_evenement(8, base, d, TargetProcessGuid=f"{{CIBLE-{i:04d}}}",
                             TargetImage=r"C:\Windows\System32\lsass.exe",
                             GrantedAccess="0x1F3FFF"))
        d += 1
    # 2. chargement des DLL nécessaires
    for i in range(3):
        ev.append(_evenement(7, base, d,
                             ImageLoaded=rf"C:\Windows\System32\net{i}.dll",
                             Hashes=f"SHA1=CCCC{i:04d}"))
        d += 1
    # 3. exfiltration vers le C2 — MÊME process_guid que l'injection
    for i in range(10):
        ev.append(_evenement(3, base, d, DestinationIp=IP_TOR,
                             DestinationPort=9001 if i % 2 else 443,
                             Protocol="tcp", Initiated="true"))
        d += 1
    return ev


def scenario_falsification(base: datetime) -> list[dict]:
    """
    Traces d'effacement : trous dans les record-ID et horodatage aberrant.
    Déclenche les règles forensiques R1 et R9 du Collect.
    """
    ev = []
    # séquence normale puis saut brutal de record-ID (suppression d'événements)
    for i, record in enumerate([1000, 1001, 1002, 8500, 8501]):
        ev.append(_evenement(13, base, i, RecordNumber=str(record),
                             TargetObject=rf"HKLM\SYSTEM\Cle{i}"))
    # horodatage antérieur à toute époque plausible → R1_timestomping
    ev.append({"EventID": 1, "UtcTime": "1970-01-01 00:00:00.000",
               "Computer": HOTE, "ProcessGuid": GUID,
               "Image": r"C:\Temp\suspect.exe"})
    return ev


SCENARIOS = [
    ("activité bénigne", scenario_benin),
    # attaque complète : injection + DLL + C2 dans la MÊME session, ce qui
    # permet au corrélateur de rapprocher la menace de l'anonymisation
    ("attaque complète (T1055 + C2 Tor)", scenario_attaque_complete),
    ("reconnaissance", scenario_reconnaissance),
    ("falsification de logs", scenario_falsification),
]


# -----------------------------------------------------------------------------
def verifier_systeme() -> bool:
    """Le système répond-il ? Sans lui, inutile d'injecter."""
    print("Vérification du système…")
    ok = True
    for nom, url in (("bus", BUS_URL), ("collect", COLLECT_URL),
                     ("decision", DECISION_URL)):
        try:
            with urllib.request.urlopen(f"{url}/health", timeout=5) as r:
                if r.status == 200:
                    print(f"  [OK] {nom}")
                    continue
        except Exception:
            pass
        print(f"  [X]  {nom} injoignable ({url})")
        ok = False
    if not ok:
        print("\nLe système ne répond pas. Démarrer d'abord :")
        print("    bash demarrer_systeme.sh")
        print("Puis vérifier :")
        print("    bash demarrer_systeme.sh --etat")
    return ok


def injecter(nom: str, evenements: list[dict]) -> None:
    print(f"\n→ {nom} ({len(evenements)} événements)")
    res = post(f"{COLLECT_URL}/ingest", {"events": evenements})
    if res:
        print(f"  Collect : {res.get('enriched', 0)} enrichis, "
              f"{res.get('flows', 0)} flux, "
              f"{res.get('integrity_alerts', 0)} alerte(s) d'intégrité")


def attendre_traitement(limite: float = 900.0, silence=None, minimum=None) -> None:
    """
    Attend la fin RÉELLE du traitement (voir services/attente.py).

    ⚠️ Ne plus se fier à la stabilité des compteurs : ils ne bougent pas
    pendant qu'Ollama travaille, ce qui faisait conclure trop tôt.
    """
    from attente import attendre_fin
    attendre_fin(ANALYSIS_URL, DECISION_URL, limite=limite)

def etat_final() -> None:
    """Ce que le système a retenu — à comparer avec le dashboard."""
    print("\n" + "=" * 66)
    print("  RÉSULTAT")
    print("=" * 66)

    for nom, url in (("collect", COLLECT_URL), ("analysis", ANALYSIS_URL),
                     ("decision", DECISION_URL)):
        try:
            # timeout large : Analysis peut être occupé par une interprétation
            # Ollama, qui prend des dizaines de secondes sur CPU
            with urllib.request.urlopen(f"{url}/stats", timeout=45) as r:
                d = json.load(r)
                print(f"  {nom:10s} {d.get('counters', {})}")
        except Exception:
            print(f"  {nom:10s} (indisponible)")

    try:
        with urllib.request.urlopen(f"{BUS_URL}/state", timeout=5) as r:
            d = json.load(r)
            print(f"\n  dashboard : {len(d.get('hosts', {}))} hôte(s), "
                  f"{len(d.get('attacks', {}))} attaque(s), "
                  f"{len(d.get('cooperation', []))} échange(s) inter-agents")
    except Exception:
        pass

    # messages d'escalade éventuels
    try:
        with urllib.request.urlopen(f"{DECISION_URL}/niveau2", timeout=5) as r:
            msgs = json.load(r).get("messages", [])
            if msgs:
                print(f"\n  {len(msgs)} escalade(s) vers le Niveau 2 :")
                for m in msgs[-3:]:
                    print(f"    · {m['mission']} — {m.get('host') or m.get('entity_key')}")
                    for j in m.get("justificatifs", [])[:3]:
                        print(f"        {j}")
    except Exception:
        pass

    print(f"\n  Dashboard : {BUS_URL}/")


def main() -> None:
    p = argparse.ArgumentParser(description="Injecteur de démonstration")
    p.add_argument("--scenario", type=int, choices=range(1, len(SCENARIOS) + 1),
                   help="n'injecter qu'un scénario (1 à 5)")
    p.add_argument("--benin", action="store_true",
                   help="bruit de fond seul, sans attaque")
    p.add_argument("--boucle", action="store_true",
                   help="rejouer en continu (démonstration)")
    p.add_argument("--pause", type=float, default=4.0,
                   help="secondes entre deux scénarios")
    args = p.parse_args()

    if not verifier_systeme():
        sys.exit(1)

    print("\n" + "=" * 66)
    print("  INJECTION — ouvrir le dashboard pour suivre en direct")
    print(f"  {BUS_URL}/")
    print("=" * 66)

    if args.benin:
        choisis = [SCENARIOS[0]]
    elif args.scenario:
        choisis = [SCENARIOS[args.scenario - 1]]
    else:
        choisis = SCENARIOS

    tour = 0
    while True:
        tour += 1
        if args.boucle:
            print(f"\n───── tour {tour} ─────")
        base = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=random.randint(1, 5))
        for nom, generateur in choisis:
            injecter(nom, generateur(base))
            time.sleep(args.pause)

        # laisser à Decision le temps de son cycle (toutes les 10 s par défaut)
        print("\n  (attente de la fin du traitement…)")
        attendre_traitement()
        # laisser un cycle de décision supplémentaire (DECIDE_INTERVAL)
        time.sleep(12)
        etat_final()

        if not args.boucle:
            break
        time.sleep(10)


if __name__ == "__main__":
    main()
