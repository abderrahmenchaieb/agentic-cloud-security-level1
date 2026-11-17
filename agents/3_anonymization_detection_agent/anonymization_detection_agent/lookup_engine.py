# =============================================================================
# ÉTAPE 1 — LOOKUP (détection des anonymiseurs CONNUS)
# =============================================================================
# À partir de l'IP EXTERNE seule, on interroge :
#   - la liste des nœuds de sortie Tor (publique, Tor Project)
#   - des plages/ASN de fournisseurs VPN connus
#
# Rapide, déterministe, haute précision sur les cas connus.
# Angles morts (→ passés à l'étape 2 GNN) : VPN résidentiels, IP nouvelles,
# serveurs auto-hébergés, endpoints VPN d'entreprise.
#
# Ici, les sources sont chargées depuis des fichiers/ensembles. En production,
# la liste Tor se rafraîchit périodiquement (URL publique) ; les plages VPN
# viennent de bases commerciales ou de listes ASN.
# =============================================================================

from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
import ipaddress

from .flow_schema import NetworkFlow, AnonymizationVerdict, AnonymizationLabel


class TorExitList:
    """
    Ensemble des IP de nœuds de sortie Tor.
    En production : rafraîchi depuis https://check.torproject.org/exit-addresses
    ou les listes du Tor Project. Ici : ensemble d'IP fourni.
    """
    def __init__(self, exit_ips: Optional[set[str]] = None):
        self._exits: set[str] = exit_ips or set()
        # ⚠️ Plages CIDR, en complément des IP unitaires.
        #    La liste officielle du Tor Project fournit des adresses précises,
        #    mais elle peut être injoignable (réseau filtré, service
        #    momentanément indisponible). Les plages hébergeant historiquement
        #    des relais permettent alors une reconnaissance partielle plutôt
        #    qu'aucune — et surtout, elles évitent qu'un nœud Tor soit
        #    étiqueté « vpn » par une plage VPN trop large.
        self._ranges: list = []

    def add(self, ip: str):
        self._exits.add(ip)

    def add_range(self, cidr: str):
        import ipaddress
        self._ranges.append(ipaddress.ip_network(cidr, strict=False))

    def load(self, ips: list[str]):
        self._exits.update(ips)

    def contains(self, ip: str) -> bool:
        if ip in self._exits:
            return True
        if self._ranges:
            import ipaddress
            try:
                a = ipaddress.ip_address(ip)
                return any(a in r for r in self._ranges)
            except ValueError:
                return False
        return False

    def __len__(self):
        return len(self._exits)


class VpnRangeDb:
    """
    Base de plages IP connues comme VPN (CIDR) + ASN de fournisseurs VPN.
    En production : bases commerciales (IPinfo, IP2Location) ou listes ASN
    de fournisseurs (NordVPN, ExpressVPN, datacenters d'hébergement...).
    """
    def __init__(self):
        self._networks: list[ipaddress._BaseNetwork] = []
        self._asns: set[int] = set()
        self._ip_asn: dict[str, int] = {}   # résolution IP → ASN (simplifiée)

    def add_range(self, cidr: str):
        self._networks.append(ipaddress.ip_network(cidr, strict=False))

    def add_asn(self, asn: int):
        self._asns.add(asn)

    def set_ip_asn(self, ip: str, asn: int):
        self._ip_asn[ip] = asn

    def contains_ip(self, ip: str) -> bool:
        # match par plage CIDR
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for net in self._networks:
            if addr in net:
                return True
        # match par ASN connu
        asn = self._ip_asn.get(ip)
        if asn is not None and asn in self._asns:
            return True
        return False


@dataclass
class LookupResult:
    matched: bool
    label: AnonymizationLabel
    source: str          # "tor_list" | "vpn_range" | "vpn_asn" | ""


class LookupEngine:
    """Étape 1 : détecte les anonymiseurs connus à partir de l'IP externe."""

    def __init__(self, tor_list: Optional[TorExitList] = None,
                 vpn_db: Optional[VpnRangeDb] = None):
        self.tor_list = tor_list or TorExitList()
        self.vpn_db = vpn_db or VpnRangeDb()

    def lookup_ip(self, ip: str) -> LookupResult:
        # Tor d'abord (signature la plus fiable)
        if self.tor_list.contains(ip):
            return LookupResult(matched=True, label=AnonymizationLabel.TOR, source="tor_list")
        # VPN ensuite
        if self.vpn_db.contains_ip(ip):
            return LookupResult(matched=True, label=AnonymizationLabel.VPN, source="vpn_range")
        return LookupResult(matched=False, label=AnonymizationLabel.UNKNOWN, source="")

    def analyze(self, flow: NetworkFlow) -> Optional[AnonymizationVerdict]:
        """
        Renvoie un verdict SI l'IP est connue (match lookup), sinon None
        (le flux passera alors à l'étape 2 GNN).

        ⚠️ LES DEUX EXTRÉMITÉS SONT INTERROGÉES
            `external_ip()` doit choisir une seule adresse, et retourne `dst`
            par défaut quand les deux sont publiques. Or sur la voie cloud
            l'attaquant appelle DEPUIS l'extérieur vers un endpoint AWS :
            l'adresse suspecte est alors la SOURCE, et la tester seule via
            `dst` la manquerait systématiquement.

            On interroge donc les deux, et on retient celle qui est reconnue.
        """
        candidates = []
        ext_ip = flow.external_ip()
        if ext_ip:
            candidates.append(ext_ip)
        for ip in (flow.src_ip, flow.dst_ip):
            if ip and ip not in candidates:
                candidates.append(ip)

        for ip in candidates:
            result = self.lookup_ip(ip)
            if result.matched:
                return AnonymizationVerdict(
                    flow_id=flow.flow_id,
                    external_ip=ip,
                    label=result.label,
                    confidence=0.99,        # lookup = très haute confiance sur les connus
                    method="lookup",
                    detail=f"IP trouvée dans {result.source}",
                )
        return None  # aucune extrémité connue → étape 2 (GNN)
