"""
=============================================================================
E1 — INTÉGRITÉ FONCTIONNELLE DU PIPELINE
=============================================================================
Le système transporte-t-il fidèlement ce qu'on lui donne ?

⚠️ POURQUOI CETTE EXPÉRIENCE PRÉCÈDE TOUTES LES AUTRES
    Mesurer un rappel de détection n'a aucun sens si des événements se
    perdent en route : un faux négatif dû à une donnée jamais arrivée n'est
    pas une erreur du modèle, mais une erreur du transport. Les deux se
    confondent dans la métrique finale.

    E1 établit donc la condition de validité de E2 à E5 : ce qui entre
    ressort, et ce qui est rejeté l'est pour une raison identifiable.

CE QUI EST MESURÉ

  1. CONSERVATION      événements soumis = événements enrichis ?
                       Toute différence est une perte à expliquer.

  2. PROPAGATION       les logs enrichis atteignent-ils Analysis ?
                       les flux atteignent-ils Anonymization ?
                       les signaux d'intégrité atteignent-ils Decision ?

  3. REJETS            un log malformé est-il ÉCARTÉ et COMPTÉ, jamais
                       ignoré en silence ? Un rejet non tracé est une perte
                       déguisée.

  4. ROUTAGE           un événement CloudTrail part-il sur la voie cloud,
                       un événement Sysmon sur la voie Windows ?

  5. RÉSILIENCE        que devient un lot quand le destinataire est
                       indisponible ? La file de retransmission doit le
                       conserver, pas l'abandonner.

CE QUI N'EST PAS MESURÉ ICI
    Ni la qualité de détection (E2), ni la robustesse aux falsifications
    (E3), ni la corrélation (E4). E1 ne regarde que le TRANSPORT.

USAGE
    python3 E1_integrite_fonctionnelle.py
    python3 E1_integrite_fonctionnelle.py --volume 500
=============================================================================
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone

_ICI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _ICI)

from campagne import etat_propre, instantane, _delta, AGENTS, BUS_URL, _get, _post


# =============================================================================
# Générateurs de charge — volontairement SIMPLES : on mesure le transport,
# pas la capacité à détecter quoi que ce soit.
# =============================================================================
def evenements_sysmon(n: int, base: datetime, hote: str = "E1-WIN") -> list[dict]:
    """n événements Sysmon valides, sans aucune anomalie."""
    return [{
        "EventID": 13,
        "UtcTime": (base + timedelta(seconds=i)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "Computer": hote, "ProcessGuid": "{E1-0000-0000-0001}",
        "Image": r"C:\Windows\System32\svchost.exe",
        "TargetObject": rf"HKLM\SOFTWARE\Test\Cle{i}",
    } for i in range(n)]


def evenements_cloudtrail(n: int, base: datetime) -> list[dict]:
    """n appels CloudTrail valides, antérieurs à l'instant d'ingestion."""
    return [{
        "eventVersion": "1.08",
        "eventTime": (base + timedelta(seconds=i)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventSource": "ec2.amazonaws.com", "eventName": "DescribeInstances",
        "awsRegion": "eu-west-1", "sourceIPAddress": "203.0.113.10",
        "userAgent": "aws-cli/2.0", "eventType": "AwsApiCall",
        "userIdentity": {"type": "IAMUser",
                         "arn": "arn:aws:iam::111111111111:user/e1-test"},
        "requestParameters": {}, "eventID": f"e1-{i:05d}",
        "recipientAccountId": "111111111111",
    } for i in range(n)]


def evenements_malformes(n: int) -> list[dict]:
    """
    n événements INVALIDES, chacun d'un type différent.

    Ils doivent être REJETÉS et COMPTÉS. Un rejet silencieux serait une
    perte déguisée : le système afficherait un traitement complet alors
    qu'il aurait écarté des données sans le dire.
    """
    modeles = [
        {},                                              # vide
        {"EventID": 1},                                  # sans horodatage
        {"UtcTime": "2026-01-01 00:00:00.000"},          # sans EventID
        {"EventID": "abc", "UtcTime": "x", "Computer": "H"},  # types invalides
        {"EventID": 1, "UtcTime": "pas-une-date", "Computer": "H"},
    ]
    return [dict(modeles[i % len(modeles)]) for i in range(n)]


# =============================================================================
def _sonde(url: str) -> dict:
    return (_get(f"{url}/stats") or {}).get("counters", {})


def mesurer_conservation(n: int, base: datetime) -> dict:
    """1 — ce qui entre ressort-il ?"""
    print(f"\n  [1] CONSERVATION — {n} événements Sysmon valides")
    avant = _sonde(AGENTS["collect"])
    ev = evenements_sysmon(n, base)
    rep = _post(f"{AGENTS['collect']}/ingest", {"events": ev}, timeout=120)
    time.sleep(2)
    apres = _sonde(AGENTS["collect"])

    recus = apres.get("received", 0) - avant.get("received", 0)
    enrichis = apres.get("enriched", 0) - avant.get("enriched", 0)
    rejetes = apres.get("rejected", 0) - avant.get("rejected", 0)
    perte = n - enrichis - rejetes

    print(f"      soumis {n} | reçus {recus} | enrichis {enrichis} | "
          f"rejetés {rejetes}")
    print(f"      → perte : {perte} "
          f"({'AUCUNE' if perte == 0 else 'ANOMALIE'})")
    return {"soumis": n, "recus": recus, "enrichis": enrichis,
            "rejetes": rejetes, "perte": perte,
            "taux_conservation": round(enrichis / n, 4) if n else 0.0}


def mesurer_rejets(n: int) -> dict:
    """3 — les malformés sont-ils écartés ET comptés ?"""
    print(f"\n  [3] REJETS — {n} événements volontairement invalides")
    avant = _sonde(AGENTS["collect"])
    _post(f"{AGENTS['collect']}/ingest", {"events": evenements_malformes(n)},
          timeout=120)
    time.sleep(2)
    apres = _sonde(AGENTS["collect"])

    rejetes = apres.get("rejected", 0) - avant.get("rejected", 0)
    enrichis = apres.get("enriched", 0) - avant.get("enriched", 0)
    print(f"      soumis {n} | rejetés {rejetes} | enrichis à tort {enrichis}")
    silencieux = n - rejetes - enrichis
    print(f"      → rejets tracés : {rejetes}/{n}"
          f"{f'  ⚠️ {silencieux} disparu(s) sans trace' if silencieux else ''}")
    return {"soumis": n, "rejetes": rejetes, "acceptes_a_tort": enrichis,
            "disparus_sans_trace": silencieux}


def mesurer_routage(n: int, base: datetime) -> dict:
    """4 — chaque source part-elle sur la bonne voie ?"""
    print(f"\n  [4] ROUTAGE — {n} événements CloudTrail")
    avant_c = _sonde(AGENTS["collect"])
    avant_a = _sonde(AGENTS["analysis"])
    _post(f"{AGENTS['collect']}/ingest",
          {"events": evenements_cloudtrail(n, base), "source": "cloudtrail"},
          timeout=120)
    time.sleep(4)
    apres_c = _sonde(AGENTS["collect"])
    apres_a = _sonde(AGENTS["analysis"])

    enrichis = apres_c.get("enriched", 0) - avant_c.get("enriched", 0)
    rejetes = apres_c.get("rejected", 0) - avant_c.get("rejected", 0)
    recus_analysis = apres_a.get("events", 0) - avant_a.get("events", 0)
    print(f"      enrichis {enrichis} | rejetés {rejetes} | "
          f"reçus par Analysis {recus_analysis}")
    ok = rejetes == 0 and enrichis == n
    print(f"      → routage cloud : {'correct' if ok else 'DÉFAILLANT'}")
    return {"soumis": n, "enrichis": enrichis, "rejetes": rejetes,
            "propages_analysis": recus_analysis, "correct": ok}


def mesurer_propagation(base: datetime) -> dict:
    """2 — les sorties atteignent-elles leurs destinataires ?"""
    print(f"\n  [2] PROPAGATION — vers Analysis, Anonymization et Decision")
    avant = instantane()
    # un lot qui produit les TROIS types de sortie
    ev = evenements_sysmon(20, base, hote="E1-PROPAG")
    ev += [{
        "EventID": 3,
        "UtcTime": (base + timedelta(seconds=30 + i)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "Computer": "E1-PROPAG", "ProcessGuid": "{E1-0000-0000-0001}",
        "Image": r"C:\Windows\System32\svchost.exe",
        "DestinationIp": "203.0.113.55", "DestinationPort": 443,
        "Protocol": "tcp", "Initiated": "true",
    } for i in range(8)]
    # un événement falsifié : produit un signal d'intégrité
    ev.append({"EventID": 1, "UtcTime": "1970-01-01 00:00:00.000",
               "Computer": "E1-PROPAG", "ProcessGuid": "{E1-0000-0000-0001}",
               "Image": r"C:\Temp\x.exe"})

    _post(f"{AGENTS['collect']}/ingest", {"events": ev}, timeout=120)
    time.sleep(8)
    d = _delta(avant, instantane())

    col = d.get("collect", {})
    ana = d.get("analysis", {})
    ano = d.get("anonymization", {})
    dec = d.get("decision", {})

    lignes = [
        ("Collect → Analysis", col.get("enriched", 0), ana.get("events", 0)),
        ("Collect → Anonymization", col.get("flows", 0), ano.get("flows", 0)),
        ("Collect → Decision (intégrité)",
         col.get("integrity_alerts", 0), dec.get("signaux_integrite_recus", 0)),
    ]
    for nom, emis, recus in lignes:
        etat = "OK" if recus >= emis > 0 else ("aucun signal" if emis == 0 else "PERTE")
        print(f"      {nom:34s} émis {emis:3d} → reçus {recus:3d}  {etat}")

    return {"collect_vers_analysis": [col.get("enriched", 0), ana.get("events", 0)],
            "collect_vers_anonymization": [col.get("flows", 0), ano.get("flows", 0)],
            "collect_vers_decision": [col.get("integrity_alerts", 0),
                                      dec.get("signaux_integrite_recus", 0)]}


def mesurer_resilience(base: datetime) -> dict:
    """
    5 — un destinataire indisponible entraîne-t-il une perte ?

    On ne peut pas arrêter un conteneur depuis ce script ; on s'appuie donc
    sur les compteurs de la file de retransmission, qui traduisent ce qui
    s'est passé si un destinataire a été momentanément injoignable.
    """
    print(f"\n  [5] RÉSILIENCE — file de retransmission")
    st = _get(f"{AGENTS['collect']}/stats") or {}
    c = st.get("counters", {})
    attente = st.get("en_attente", {})
    print(f"      réessais réussis {c.get('reessais', 0)} | "
          f"lots abandonnés {c.get('perdus', 0)}")
    print(f"      en attente : {attente}")
    perdus = c.get("perdus", 0)
    print(f"      → {'aucune perte' if perdus == 0 else f'{perdus} lot(s) PERDU(S)'}")
    return {"reessais": c.get("reessais", 0), "perdus": perdus,
            "en_attente": attente}


# =============================================================================
def main() -> None:
    p = argparse.ArgumentParser(description="E1 — intégrité fonctionnelle")
    p.add_argument("--volume", type=int, default=300,
                   help="nombre d'événements par mesure")
    p.add_argument("--json", default="E1_integrite_fonctionnelle.json")
    args = p.parse_args()

    print("=" * 70)
    print("  E1 — INTÉGRITÉ FONCTIONNELLE DU PIPELINE")
    print("=" * 70)
    print("  Établit la condition de validité de E2 à E5 : ce qui entre")
    print("  ressort, et ce qui est écarté l'est pour une raison tracée.")

    if not _get(f"{BUS_URL}/health"):
        print("\n  système injoignable — démarrer la pile d'abord.")
        sys.exit(1)
    if not etat_propre():
        print("\n  état non propre — mesures abandonnées.")
        sys.exit(1)

    base = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=1)
    n = args.volume

    resultats = {
        "conservation": mesurer_conservation(n, base),
        "propagation": mesurer_propagation(base + timedelta(minutes=5)),
        "rejets": mesurer_rejets(max(20, n // 10)),
        "routage": mesurer_routage(max(20, n // 10), base + timedelta(minutes=10)),
        "resilience": mesurer_resilience(base),
    }

    # --- verdict -------------------------------------------------------
    print(f"\n{'=' * 70}\n  VERDICT E1\n{'=' * 70}")
    cons = resultats["conservation"]
    rej = resultats["rejets"]
    rout = resultats["routage"]
    res = resultats["resilience"]

    controles = [
        ("aucune perte à l'ingestion", cons["perte"] == 0),
        ("taux de conservation ≥ 99 %", cons["taux_conservation"] >= 0.99),
        ("malformés tous tracés", rej["disparus_sans_trace"] == 0),
        ("malformés non acceptés à tort", rej["acceptes_a_tort"] == 0),
        ("routage cloud correct", rout["correct"]),
        ("aucun lot perdu", res["perdus"] == 0),
    ]
    for libelle, ok in controles:
        print(f"    [{'OK' if ok else ' X'}] {libelle}")

    valide = all(ok for _, ok in controles)
    print()
    if valide:
        print("  → PIPELINE FIDÈLE. Les mesures de E2 à E5 porteront sur des")
        print("    données effectivement transportées : un faux négatif y sera")
        print("    imputable au modèle, non à une perte de transport.")
    else:
        print("  → PIPELINE NON FIDÈLE. Poursuivre la campagne produirait des")
        print("    métriques ininterprétables : une donnée perdue en transport")
        print("    apparaîtrait comme une erreur de détection.")

    resultats["verdict"] = {"valide": valide,
                            "controles": {l: ok for l, ok in controles}}
    with open(args.json, "w", encoding="utf-8") as f:
        json.dump(resultats, f, ensure_ascii=False, indent=2)
    print(f"\n  résultats exportés : {args.json}")


if __name__ == "__main__":
    main()
