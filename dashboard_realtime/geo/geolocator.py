# =============================================================================
# SERVICE DE GÉOLOCALISATION (utilitaire partagé — PAS un agent)
# =============================================================================
# Traduit une IP en position approximative pour la CARTE du dashboard.
# Ce n'est pas un agent (il ne perçoit/décide/agit pas) : c'est une CONSULTATION
# de base de données, comme la base D3FEND que le Decision consulte.
#
# Deux niveaux de géolocalisation, cohérents avec l'architecture :
#   - CE SERVICE : lookup simple (pays, ville, lat/lon) — APPROXIMATIF.
#   - NIVEAU 2   : géoloc approfondie derrière l'anonymisation (hors périmètre).
#
# LOGIQUE HONNÊTE (cœur de la thèse) : pour une IP détectée anonymisée (Tor/VPN)
# par l'Anonymization Agent, la position rendue est celle du RELAIS (nœud de
# sortie / serveur VPN), PAS de l'attaquant. Le service la marque
# position_is_real=False. On ne prétend jamais localiser un attaquant masqué.
#
# Sources de base compatibles (format .mmdb) : MaxMind GeoLite2, DB-IP Lite
# (licence CC-BY, villes incluses), IPLocate (sans paperasse). Toutes se lisent
# avec geoip2. La base n'est PAS incluse ici (licence/taille) : déposer le
# fichier .mmdb et renseigner son chemin.
# =============================================================================

from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass
class GeoResult:
    ip: str
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    country: Optional[str] = None
    city: Optional[str] = None
    # HONNÊTETÉ : True = position approximative de l'IP réelle ;
    #             False = l'IP est un relais d'anonymisation (position != attaquant)
    position_is_real: bool = True
    ip_kind: str = "clear"          # clear | tor | vpn
    accuracy: str = "approximate"   # rappel : la géoloc IP est toujours approximative
    detail: str = ""
    found: bool = True


# -----------------------------------------------------------------------------
# Interface commune
# -----------------------------------------------------------------------------
class GeoLocator(ABC):
    @abstractmethod
    def _raw_lookup(self, ip: str) -> Optional[dict]:
        """Retourne {latitude, longitude, country, city} ou None si introuvable."""
        ...

    def locate(self, ip: str, anonymization: str = "clear") -> GeoResult:
        """
        Localise une IP. 'anonymization' vient de l'Anonymization Agent :
        'clear' | 'tor' | 'vpn'. Si anonymisée, la position est celle du relais
        et position_is_real=False (on ne localise pas l'attaquant réel).
        """
        raw = self._raw_lookup(ip)
        if raw is None:
            return GeoResult(ip=ip, found=False, ip_kind=anonymization,
                             detail="IP introuvable dans la base géo")

        is_anon = anonymization in ("tor", "vpn")
        if is_anon:
            relais = "nœud de sortie Tor" if anonymization == "tor" else "serveur VPN"
            detail = (f"position du {relais}, PAS de l'attaquant — "
                      f"origine réelle à percer par le Niveau 2")
        else:
            detail = "position approximative de l'IP"

        return GeoResult(
            ip=ip, latitude=raw.get("latitude"), longitude=raw.get("longitude"),
            country=raw.get("country"), city=raw.get("city"),
            position_is_real=not is_anon, ip_kind=anonymization,
            accuracy="approximate", detail=detail, found=True,
        )


# -----------------------------------------------------------------------------
# Implémentation 1 : base .mmdb réelle (MaxMind / DB-IP / IPLocate)
# -----------------------------------------------------------------------------
class MmdbGeoLocator(GeoLocator):
    """Lit une base .mmdb (format MaxMind, compatible DB-IP/IPLocate)."""

    def __init__(self, mmdb_path: str):
        import geoip2.database
        self._reader = geoip2.database.Reader(mmdb_path)

    def _raw_lookup(self, ip: str) -> Optional[dict]:
        try:
            r = self._reader.city(ip)
            return {"latitude": r.location.latitude, "longitude": r.location.longitude,
                    "country": r.country.iso_code, "city": r.city.name}
        except Exception:
            return None

    def close(self):
        self._reader.close()


# -----------------------------------------------------------------------------
# Implémentation 2 : base de DÉMONSTRATION (en attendant la vraie base)
# -----------------------------------------------------------------------------
class DemoGeoLocator(GeoLocator):
    """
    Petit jeu de positions connues, pour faire tourner la carte MAINTENANT
    sans dépendre d'un téléchargement. À remplacer par MmdbGeoLocator en
    déposant une vraie base .mmdb.
    """
    _DEMO = {
        "203.0.113.9":     {"latitude": 48.8566, "longitude": 2.3522, "country": "FR", "city": "Paris"},
        "198.51.100.22":   {"latitude": 40.7128, "longitude": -74.0060, "country": "US", "city": "New York"},
        "8.8.8.8":         {"latitude": 37.4056, "longitude": -122.0775, "country": "US", "city": "Mountain View"},
        # relais d'anonymisation (positions des RELAIS, pas des attaquants)
        "185.220.101.47":  {"latitude": 50.1109, "longitude": 8.6821, "country": "DE", "city": "Frankfurt"},   # Tor exit
        "45.83.220.10":    {"latitude": 52.3676, "longitude": 4.9041, "country": "NL", "city": "Amsterdam"},   # VPN
        "104.28.0.1":      {"latitude": 51.5074, "longitude": -0.1278, "country": "GB", "city": "London"},
    }

    def _raw_lookup(self, ip: str) -> Optional[dict]:
        return self._DEMO.get(ip)


# -----------------------------------------------------------------------------
# Fabrique : vraie base si disponible, sinon démo
# -----------------------------------------------------------------------------
def make_geolocator(mmdb_path: Optional[str] = None) -> GeoLocator:
    """
    Retourne un MmdbGeoLocator si un chemin .mmdb valide est fourni,
    sinon un DemoGeoLocator (pour que la carte fonctionne sans la base).
    """
    if mmdb_path:
        import os
        if not os.path.exists(mmdb_path):
            print(f"[geo] base introuvable : {mmdb_path} — mode approximatif",
                  flush=True)
        else:
            try:
                loc = MmdbGeoLocator(mmdb_path)
                print(f"[geo] base chargée : {mmdb_path}", flush=True)
                return loc
            except ImportError:
                # ⚠️ Cause la plus fréquente : geoip2 absent de l'image. Le
                #    repli silencieux laissait croire que la base était lue,
                #    alors que seules quelques plages publiques connues du
                #    mode démo étaient résolues.
                print("[geo] geoip2 non installé — la base .mmdb ne peut pas "
                      "être lue. Ajouter geoip2 aux dépendances du bus et "
                      "RECONSTRUIRE l'image (un simple restart ne suffit pas).",
                      flush=True)
            except Exception as e:
                print(f"[geo] base illisible ({type(e).__name__}: {e}) — "
                      f"mode approximatif", flush=True)
    return DemoGeoLocator()
