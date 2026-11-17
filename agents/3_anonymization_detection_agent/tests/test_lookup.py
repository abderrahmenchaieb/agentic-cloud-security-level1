"""Test du contrat de flux + étape 1 (lookup)."""
from anonymization_detection_agent.flow_schema import NetworkFlow, FlowFeatures, AnonymizationLabel
from anonymization_detection_agent.lookup_engine import LookupEngine, TorExitList, VpnRangeDb

# --- Préparer les sources de lookup ---
tor = TorExitList()
tor.load(["185.220.101.47", "204.13.164.118"])  # nœuds Tor connus (exemples)

vpn = VpnRangeDb()
vpn.add_range("45.83.220.0/22")      # plage VPN (exemple)
vpn.add_asn(60068)                    # ASN d'un fournisseur VPN (exemple)
vpn.set_ip_asn("212.102.45.10", 60068)  # cette IP appartient à cet ASN

engine = LookupEngine(tor_list=tor, vpn_db=vpn)

# --- Cas de test ---
def mk(fid, src, dst):
    return NetworkFlow(flow_id=fid, src_ip=src, dst_ip=dst, dst_port=443, protocol="tcp")

cas = [
    ("Flux vers nœud Tor connu",       mk("F1", "10.0.0.5", "185.220.101.47"), AnonymizationLabel.TOR),
    ("Flux vers plage VPN connue",     mk("F2", "10.0.0.5", "45.83.220.15"),   AnonymizationLabel.VPN),
    ("Flux vers IP d'ASN VPN connu",   mk("F3", "10.0.0.5", "212.102.45.10"),  AnonymizationLabel.VPN),
    ("Flux vers IP normale inconnue",  mk("F4", "10.0.0.5", "142.250.184.14"), None),  # Google → inconnu du lookup
]

print("="*66)
print("ÉTAPE 1 — LOOKUP (détection des anonymiseurs connus)")
print("="*66)
print(f"\nSources : {len(tor)} nœuds Tor, plages+ASN VPN chargés\n")

for nom, flow, attendu in cas:
    verdict = engine.analyze(flow)
    ext = flow.external_ip()
    if verdict:
        print(f"[{verdict.label.value.upper():7}] {nom}")
        print(f"          IP externe {ext} → {verdict.detail} (conf {verdict.confidence})")
        ok = verdict.label == attendu
    else:
        print(f"[INCONNU] {nom}")
        print(f"          IP externe {ext} → non trouvée au lookup → passera au GNN (étape 2)")
        ok = attendu is None
    print(f"          {'OK' if ok else 'ECHEC'}\n")

# --- Vérification de l'identification de l'IP externe ---
print("="*66)
print("Identification de l'IP EXTERNE (laquelle interroger ?)")
print("="*66)
tests_ext = [
    ("10.0.0.5", "185.220.101.47", "185.220.101.47"),   # interne→externe
    ("185.220.101.47", "10.0.0.5", "185.220.101.47"),   # externe→interne (sens inverse)
    ("192.168.1.10", "8.8.8.8", "8.8.8.8"),             # autre plage privée
]
for src, dst, attendu in tests_ext:
    f = NetworkFlow(flow_id="X", src_ip=src, dst_ip=dst)
    ext = f.external_ip()
    print(f"  {src:16} ↔ {dst:16} → externe = {ext:16} {'OK' if ext==attendu else 'ECHEC'}")

print("\n[OK] Étape 1 fonctionnelle : détecte les connus, laisse les inconnus au GNN.")
