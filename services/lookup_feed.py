"""
=============================================================================
ALIMENTATION DU LOOKUP — listes Tor et plages VPN
=============================================================================
Étage 1 de la cascade d'anonymisation. Sans lui, aucune IP n'est reconnue :
les bases sont vides par défaut, le mécanisme existe mais n'était jamais
alimenté — d'où une carte du dashboard restant à zéro position alors que du
trafic Tor circulait.

SOURCES
    Tor : https://check.torproject.org/exit-addresses
          Liste officielle des nœuds de sortie, publiée et rafraîchie en
          continu par le Tor Project. C'est la référence du domaine.

    VPN : les bases exhaustives sont commerciales (IPinfo, IP2Location).
          À défaut, on charge les plages de datacenters les plus courantes —
          couverture partielle, assumée comme telle.

RAFRAÎCHISSEMENT
    Les nœuds de sortie Tor changent en permanence : une liste figée perd sa
    valeur en quelques jours. Le chargeur rafraîchit donc périodiquement, et
    conserve la dernière liste valide si la source devient injoignable.

⚠️ CE QUE LE LOOKUP NE COUVRE PAS
    VPN résidentiels, IP récemment mises en service, serveurs auto-hébergés,
    passerelles VPN d'entreprise. Ces angles morts justifient les étages 2 et
    3 de la cascade (E-GraphSAGE, Anomal-E), qui travaillent sur le
    comportement du flux et non sur son adresse.
=============================================================================
"""
from __future__ import annotations

import threading
import time
import urllib.request

URL_TOR = "https://check.torproject.org/exit-addresses"

# Plages de datacenters fréquemment utilisées par des services VPN.
# Couverture partielle : une base commerciale est nécessaire pour être complet.
#
# ⚠️ NE PAS Y METTRE DE PLAGES TOR.
#    `185.220.100.0/22` (soit 185.220.100.0 → 185.220.103.255) est une plage
#    de RELAIS TOR, pas de VPN. L'y inscrire faisait étiqueter « vpn » des
#    nœuds de sortie Tor que la liste officielle n'avait pas encore chargés —
#    l'IP était correcte, le type d'anonymisation faux, ce qui fausse le
#    dossier transmis au Niveau 2 (le discounting y dépend du type : un relais
#    Tor et un VPN n'ont pas la même fiabilité de signal).
PLAGES_VPN_CONNUES = [
    "51.15.0.0/16",       # Scaleway
    "51.158.0.0/15",      # Scaleway
    "45.83.0.0/16",       # datacenters européens
    "185.242.4.0/24",     # hébergeurs à usage VPN fréquent
]


# Plages hébergeant historiquement de nombreux relais de sortie Tor.
# Utilisées EN REPLI quand la liste officielle est injoignable : mieux vaut
# une couverture partielle qu'aucune reconnaissance. La liste officielle,
# quand elle se charge, reste la source de vérité.
PLAGES_TOR_CONNUES = [
    "185.220.100.0/22",   # 185.220.100-103 : relais de sortie
    "185.220.96.0/22",
    "23.129.64.0/24",
    "171.25.193.0/24",
]


def telecharger_noeuds_tor(timeout: float = 30.0) -> list[str]:
    """
    Récupère les IP de sortie Tor depuis la source officielle.

    Le format est textuel ; les adresses figurent sur les lignes commençant
    par « ExitAddress ». Renvoie une liste vide en cas d'échec — l'appelant
    conserve alors la liste précédente plutôt que de tout perdre.
    """
    try:
        req = urllib.request.Request(
            URL_TOR, headers={"User-Agent": "agentic-security/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            contenu = r.read().decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"[lookup] liste Tor inaccessible : {str(e)[:100]}", flush=True)
        return []

    ips = []
    for ligne in contenu.splitlines():
        if ligne.startswith("ExitAddress "):
            parties = ligne.split()
            if len(parties) >= 2:
                ips.append(parties[1])
    return ips


def alimenter(lookup, avec_vpn: bool = True) -> dict:
    """
    Charge les sources dans un LookupEngine existant.
    Renvoie un compte-rendu de ce qui a été chargé.
    """
    rapport = {"tor": 0, "vpn_ranges": 0}

    ips_tor = telecharger_noeuds_tor()
    if ips_tor:
        lookup.tor_list.load(ips_tor)
        rapport["tor"] = len(ips_tor)
        print(f"[lookup] {len(ips_tor)} nœuds de sortie Tor chargés", flush=True)

    # ⚠️ Les plages connues sont chargées EN COMPLÉMENT, pas seulement en repli.
    #    La liste officielle ne contient que les relais ACTIFS à l'instant du
    #    téléchargement : une adresse ayant hébergé un relais la veille en est
    #    absente. Sans les plages, elle devient inconnue du lookup — et une
    #    détection qui fonctionnait cesse de fonctionner sans que rien n'ait
    #    changé dans le système.
    for cidr in PLAGES_TOR_CONNUES:
        try:
            lookup.tor_list.add_range(cidr)
            rapport["tor_ranges"] = rapport.get("tor_ranges", 0) + 1
        except Exception:
            continue
    if rapport.get("tor_ranges"):
        print(f"[lookup] {rapport['tor_ranges']} plage(s) Tor connue(s) "
              f"chargée(s)", flush=True)

    if not ips_tor and not rapport.get("tor_ranges"):
        print(f"[lookup] aucun nœud Tor chargé — l'étage 1 ne reconnaîtra "
              f"aucune IP Tor", flush=True)

    if avec_vpn:
        for cidr in PLAGES_VPN_CONNUES:
            try:
                lookup.vpn_db.add_range(cidr)
                rapport["vpn_ranges"] += 1
            except Exception:
                continue
        print(f"[lookup] {rapport['vpn_ranges']} plage(s) VPN chargée(s) "
              f"(couverture partielle)", flush=True)

    return rapport


def demarrer_rafraichissement(lookup, intervalle: int = 3600,
                              avec_vpn: bool = True) -> threading.Thread:
    """
    Alimente immédiatement, puis rafraîchit en arrière-plan.

    Les nœuds de sortie Tor changent constamment : sans rafraîchissement, la
    détection se dégrade silencieusement au fil des jours.
    """
    alimenter(lookup, avec_vpn)

    def boucle():
        while True:
            time.sleep(intervalle)
            try:
                ips = telecharger_noeuds_tor()
                if ips:                     # ne remplacer que si le téléchargement
                    lookup.tor_list.load(ips)   # a réussi : garder l'ancienne sinon
                    print(f"[lookup] liste Tor rafraîchie ({len(ips)} nœuds)",
                          flush=True)
            except Exception as e:
                print(f"[lookup] rafraîchissement ignoré : {e}", flush=True)

    fil = threading.Thread(target=boucle, daemon=True)
    fil.start()
    return fil
