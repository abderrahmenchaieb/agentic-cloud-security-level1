"""
=============================================================================
SERVICE — AGENT ANONYMIZATION
=============================================================================
Point d'entrée exécutable de l'agent Anonymization, destiné à son conteneur.

CE QUE FAIT CE SERVICE
    1. charge la cascade : lookup → E-GraphSAGE (décideur) → Anomal-E (filet)
    2. se connecte au bus — cet agent est ÉMETTEUR de `attention_hint`
       vers Analysis ; il n'enregistre aucun handler
    3. expose :
         POST /ingest   ← Collect y pousse les flux réseau
         POST /handle   ← le bus y relaie d'éventuelles requêtes
         GET  /health   ← sonde de santé
         GET  /stats    ← compteurs et effort de cascade
    4. transmet les verdicts d'anonymisation à Decision

⚠️ E-GRAPHSAGE — TROIS DIFFÉRENCES AVEC LES AUTRES MODÈLES
    1. C'est un GNN : il opère sur un GRAPHE (nœuds = IP, arêtes = flux),
       pas sur des vecteurs indépendants. Un flux isolé ne peut pas être
       classé seul — d'où le traitement par LOT.
    2. Il a été entraîné AVEC un StandardScaler : son scaler DOIT être
       appliqué aux 76 features d'arête. C'est l'inverse exact des
       RandomForest d'Analysis, entraînés sur features brutes (scaler
       identité). Se tromper produit des prédictions fausses sans erreur.
    3. Ses classes sont {0: normal, 1: VPN, 2: Tor}, avec une pondération
       Tor ×8 à l'entraînement (rappel privilégié sur la classe rare).

VARIABLES D'ENVIRONNEMENT
    BUS_URL, AGENT_URL, DECISION_URL, MODELS_DIR, PORT
    ENABLE_ANOMALE   "0" pour désactiver le filet auto-supervisé
=============================================================================
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_ROOT = os.environ.get("SYSTEM_ROOT", os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
for _p in (_ROOT,
           os.path.join(_ROOT, "agents", "3_anonymization_detection_agent"),
           os.path.join(_ROOT, "agentic_layer")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from anonymization_detection_agent.anonymization_detection_agent import (
    AnonymizationDetectionAgent)
from anonymization_detection_agent.flow_schema import NetworkFlow, FlowFeatures
from anonymization_detection_agent.lookup_engine import LookupEngine
from agentic_layer.agent_bus_http import AgentBusHTTP
from agentic_layer.agentic_anonymization import AgenticAnonymizationAgent

BUS_URL        = os.environ.get("BUS_URL", "http://bus:8000")
AGENT_URL      = os.environ.get("AGENT_URL", "http://anonymization:9003")
DECISION_URL   = os.environ.get("DECISION_URL", "http://decision:9004")
MODELS_DIR     = os.environ.get("MODELS_DIR", os.path.join(_ROOT, "models"))
PORT           = int(os.environ.get("PORT", "9003"))
ENABLE_ANOMALE = os.environ.get("ENABLE_ANOMALE", "1") == "1"

AGENT_NAME = "anonymization"


def post_json(url: str, payload: dict, timeout: float = 30.0):
    import urllib.request
    data = json.dumps(payload, default=str).encode("utf-8")
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8")
            return json.loads(body) if body else {}
    except Exception:
        return None


# -----------------------------------------------------------------------------
# Chargement des modèles de la cascade
# -----------------------------------------------------------------------------
def _features_modele() -> list[str]:
    """Noms des 76 features d'arête, lus dans la configuration du modèle."""
    import joblib
    try:
        return list(joblib.load(
            os.path.join(MODELS_DIR, "egraphsage_config.pkl"))["feature_cols"])
    except Exception:
        return []


def check_feature_compatibility(edge_dim_attendu: int) -> tuple[bool, int]:
    """
    Vérifie que le GraphBuilder produit le nombre de features d'arête attendu
    par E-GraphSAGE.

    ⚠️ PRÉREQUIS DE DÉPLOIEMENT — SOURCE PCAP REQUISE
        E-GraphSAGE a été entraîné sur CIC-Darknet2020, dont les 76 features
        d'arête (« Flow Duration », « Fwd Packet Length Std »…) sont produites
        par CICFlowMeter à partir d'une CAPTURE RÉSEAU (PCAP).

        Un événement Sysmon EventID 3 ne fournit que source, destination,
        ports et protocole — aucune statistique de flux. Sur une source Sysmon
        seule, le GraphBuilder ne produit que 12 features : le GNN ne peut pas
        s'exécuter.

        Pour activer E-GraphSAGE en production, il faut alimenter l'agent
        depuis une capture réseau traitée par CICFlowMeter. À défaut, la
        cascade se limite à l'étage 1 (lookup d'IP Tor/VPN connues), qui reste
        opérationnel et utile.
    """
    try:
        from anonymization_detection_agent.flow_schema import NetworkFlow, FlowFeatures
        from anonymization_detection_agent.graph_builder import GraphBuilder
        from anonymization_detection_agent.egraphsage import graph_to_tensors
        # ⚠️ La sonde doit refléter la CONFIGURATION réelle, pas un flux vide.
        #    Le GraphBuilder produit autant de features que la liste qu'on lui
        #    passe : avec les 76 noms du modèle, il en produit 76. Tester avec
        #    la liste par défaut (13 noms) concluait à tort à une
        #    incompatibilité et désactivait le GNN.
        noms = _features_modele()
        sonde = [NetworkFlow(flow_id="probe", src_ip="10.0.0.1", dst_ip="1.2.3.4",
                             features=FlowFeatures())]
        _, edge_feat, _ = graph_to_tensors(
            GraphBuilder(edge_features=noms).build(sonde, normalize=True))
        produit = int(edge_feat.shape[1])
        return produit == edge_dim_attendu, produit
    except Exception:
        return False, 0


def load_egraphsage():
    """
    Charge E-GraphSAGE et son scaler. Renvoie (modèle, scaler, config) ou
    (None, None, None) : sans lui, la cascade se réduit au lookup, ce qui
    reste utile pour les IP déjà connues.
    """
    p_mdl = os.path.join(MODELS_DIR, "egraphsage_model.pt")
    p_scl = os.path.join(MODELS_DIR, "egraphsage_scaler.pkl")
    p_cfg = os.path.join(MODELS_DIR, "egraphsage_config.pkl")
    if not all(os.path.exists(p) for p in (p_mdl, p_scl, p_cfg)):
        print(f"[{AGENT_NAME}] E-GraphSAGE absent de {MODELS_DIR} — "
              f"cascade réduite au lookup", flush=True)
        return None, None, None
    try:
        import torch, joblib
        from anonymization_detection_agent.egraphsage import EGraphSAGE
        cfg = joblib.load(p_cfg)
        edge_dim = int(cfg.get("edge_dim", 76))

        # Refuser d'activer un modèle qui ne peut pas s'exécuter, plutôt que
        # de laisser l'erreur de dimensions surgir à la première inférence.
        compatible, produit = check_feature_compatibility(edge_dim)
        if not compatible:
            print(f"[{AGENT_NAME}] E-GraphSAGE DÉSACTIVÉ — désalignement de "
                  f"features : le modèle attend {edge_dim} features d'arête "
                  f"(CIC-Darknet2020 / CICFlowMeter), la source en produit "
                  f"{produit}.", flush=True)
            print(f"[{AGENT_NAME}] → une source PCAP traitée par CICFlowMeter "
                  f"est requise ; la cascade se limite au lookup.", flush=True)
            return None, None, cfg

        model = EGraphSAGE(edge_dim=edge_dim,
                           hidden_dim=int(cfg.get("hidden_dim", 64)),
                           n_classes=int(cfg.get("n_classes", 3)),
                           n_layers=int(cfg.get("n_layers", 2)))
        model.load_state_dict(torch.load(p_mdl, map_location="cpu",
                                         weights_only=True))
        model.eval()
        scaler = joblib.load(p_scl)
        print(f"[{AGENT_NAME}] E-GraphSAGE chargé "
              f"(edge_dim={edge_dim}, classes={cfg.get('class_mapping')})",
              flush=True)
        return model, scaler, cfg
    except Exception as e:
        print(f"[{AGENT_NAME}] échec du chargement E-GraphSAGE : {e}", flush=True)
        return None, None, None


def load_anomale():
    """Charge le filet auto-supervisé (DGI + IsolationForest). Optionnel."""
    if not ENABLE_ANOMALE:
        return None
    p_dgi = os.path.join(MODELS_DIR, "anomale_dgi.pt")
    p_iso = os.path.join(MODELS_DIR, "anomale_isoforest.pkl")
    p_cfg = os.path.join(MODELS_DIR, "anomale_config.pkl")
    if not all(os.path.exists(p) for p in (p_dgi, p_iso, p_cfg)):
        print(f"[{AGENT_NAME}] Anomal-E absent — filet désactivé", flush=True)
        return None
    try:
        import torch, joblib
        from anonymization_detection_agent.anomale import AnomalEDetector, AnomalEDGI
        cfg = joblib.load(p_cfg)
        # AnomalEDetector attend un modèle DGI DÉJÀ construit, pas des dimensions
        dgi = AnomalEDGI(edge_dim=int(cfg.get("edge_dim", 76)),
                         hidden_dim=int(cfg.get("hidden_dim", 64)))
        dgi.load_state_dict(torch.load(p_dgi, map_location="cpu", weights_only=True))
        dgi.eval()
        det = AnomalEDetector(dgi_model=dgi,
                              contamination=float(cfg.get("contamination", 0.1)))
        det.iso = joblib.load(p_iso)   # IsolationForest entraîné sur les embeddings
        print(f"[{AGENT_NAME}] Anomal-E chargé (filet actif, "
              f"Tor {cfg.get('tor_recall')}, VPN {cfg.get('vpn_recall')})", flush=True)
        return det
    except Exception as e:
        print(f"[{AGENT_NAME}] Anomal-E indisponible ({e}) — filet désactivé",
              flush=True)
        return None


# -----------------------------------------------------------------------------
# Conversion des flux reçus en NetworkFlow
# -----------------------------------------------------------------------------
# champs canoniques de FlowFeatures ; tout le reste va dans `extra`
_CANONIQUES = {
    "flow_duration", "total_fwd_packets", "total_bwd_packets",
    "total_length_fwd", "total_length_bwd", "flow_bytes_per_s",
    "flow_packets_per_s", "flow_iat_mean", "flow_iat_std",
    "fwd_packet_length_mean", "bwd_packet_length_mean", "down_up_ratio",
}


def _construire_features(feats: dict) -> FlowFeatures:
    """
    Répartit les valeurs reçues entre les champs canoniques et `extra`.

    ⚠️ Les 76 features de CIC-Darknet2020 portent les noms de CICFlowMeter
    (« Flow Duration », « Fwd IAT Std »…), qui ne correspondent PAS aux
    attributs canoniques. Les passer au constructeur lèverait une erreur.
    Le schéma prévoit `extra` précisément pour cela : `to_vector` y cherche
    tout nom absent des canoniques.
    """
    if not feats:
        return FlowFeatures()
    canon, extra = {}, {}
    for k, v in feats.items():
        if not isinstance(v, (int, float)):
            continue
        (canon if k in _CANONIQUES else extra)[k] = float(v)
    return FlowFeatures(**canon, extra=extra)


def dicts_to_flows(items: list[dict]) -> list[NetworkFlow]:
    """
    Convertit les flux transmis par Collect (FlowRecord sérialisés) en
    NetworkFlow. Les features statistiques absentes valent 0 : le lookup
    reste opérationnel même sans métriques de flux complètes.
    """
    flows = []
    for i, d in enumerate(items):
        try:
            feats = d.get("features") or {}
            flows.append(NetworkFlow(
                flow_id=str(d.get("flow_id") or f"f{i}"),
                src_ip=str(d.get("src_ip") or d.get("source_ip") or ""),
                dst_ip=str(d.get("dst_ip") or d.get("destination_ip") or ""),
                src_port=d.get("src_port") or d.get("source_port"),
                dst_port=d.get("dst_port") or d.get("destination_port"),
                protocol=d.get("protocol"),
                timestamp=str(d.get("timestamp") or d.get("event_time") or ""),
                features=_construire_features(feats),
            ))
        except Exception:
            continue  # flux malformé : ignoré silencieusement
    return flows


# -----------------------------------------------------------------------------
# État du service
# -----------------------------------------------------------------------------
class ServiceState:
    def __init__(self):
        self.gnn, self.scaler, self.gnn_cfg = load_egraphsage()
        self.anomale = load_anomale()
        self.lookup = LookupEngine()
        # ⚠️ Sans alimentation, les bases Tor/VPN sont VIDES : l'étage 1 ne
        #    reconnaît aucune IP. Combiné à E-GraphSAGE inactif faute de
        #    features de flux, l'agent ne détecterait jamais rien.
        try:
            from lookup_feed import demarrer_rafraichissement
            demarrer_rafraichissement(self.lookup)
        except Exception as e:
            print(f"[{AGENT_NAME}] alimentation du lookup impossible ({e}) — "
                  f"l'étage 1 restera inopérant", flush=True)

        # ⚠️ Le GraphBuilder doit produire les features dans l'ORDRE ET LE
        #    NOMBRE attendus par E-GraphSAGE (76, nommage CIC-Darknet2020).
        #    Avec sa liste par défaut (13 noms internes), le graphe serait
        #    incompatible avec le modèle.
        from anonymization_detection_agent.graph_builder import GraphBuilder
        noms = _features_modele()
        builder = GraphBuilder(edge_features=noms) if noms else GraphBuilder()

        # ⚠️ NORMALISATION — POINT CRITIQUE
        #    `GraphBuilder._normalize` standardise avec les statistiques du LOT
        #    COURANT (moyenne et écart-type des quelques flux reçus). Or
        #    E-GraphSAGE a été entraîné avec un StandardScaler ajusté sur les
        #    141 530 flux du dataset complet.
        #
        #    Deux normalisations différentes = le modèle reçoit des valeurs
        #    sans rapport avec celles vues à l'entraînement, et produit des
        #    sorties dégénérées (tout classé « normal », confiance 1.0) SANS
        #    la moindre erreur visible.
        #
        #    On substitue donc le scaler d'entraînement à la normalisation
        #    par lot. C'est le pendant du scaler identité installé pour les
        #    RandomForest : dans les deux cas, il s'agit de reproduire
        #    exactement le traitement appliqué à l'entraînement.
        if self.scaler is not None and noms:
            scaler = self.scaler

            def _normaliser_comme_a_l_entrainement(X):
                import numpy as np
                return scaler.transform(np.asarray(X, dtype=float)).astype("float32")

            builder._normalize = _normaliser_comme_a_l_entrainement
            print(f"[{AGENT_NAME}] scaler d'entraînement appliqué "
                  f"({len(noms)} features)", flush=True)

        self.anon = AnonymizationDetectionAgent(
            lookup=self.lookup,
            graph_builder=builder,
            egraphsage_model=self.gnn,
            anomale_detector=self.anomale)
        # le scaler doit accompagner le GNN (features normalisées à l'entraînement)
        if self.scaler is not None:
            setattr(self.anon, "feature_scaler", self.scaler)

        self.bus = AgentBusHTTP(bus_url=BUS_URL, agent_url=AGENT_URL,
                                agent_name=AGENT_NAME)
        self.bus_ready = self._wait_for_bus()
        self.agentic = (AgenticAnonymizationAgent(self.anon, self.bus)
                        if self.bus_ready else None)
        # le registre du bus est en mémoire : se réinscrire s'il redémarre
        if self.bus_ready:
            self.bus.surveiller_enregistrement()
        print(f"[{AGENT_NAME}] " + ("coopération active" if self.bus_ready
                                    else "MODE DÉGRADÉ — bus injoignable"), flush=True)

        self.counters = {"flows": 0, "anonymized": 0, "tor": 0, "vpn": 0}
        self.started_at = time.time()

    def _wait_for_bus(self, retries: int = 30, delay: float = 2.0) -> bool:
        for i in range(retries):
            if self.bus.health():
                return True
            print(f"[{AGENT_NAME}] bus indisponible, tentative {i+1}/{retries}…",
                  flush=True)
            time.sleep(delay)
        return False

    # --- traitement -----------------------------------------------------------
    def ingest(self, items: list[dict], host_map: dict | None = None) -> dict:
        flows = dicts_to_flows(items)
        self.counters["flows"] += len(flows)
        if not flows:
            return {"flows": 0, "anonymized": 0}

        # ⚠️ traitement par LOT : le GNN a besoin du graphe complet
        if self.agentic is not None:
            verdicts = self.agentic.analyze_batch(flows, host_map or {})
        else:
            verdicts = self.anon.analyze_batch(flows)

        # ⚠️ AnonymizationVerdict n'a PAS d'attribut `is_anonymized` : il porte
        #    un `label` (normal / vpn / tor / unknown). Filtrer sur un attribut
        #    inexistant vidait systématiquement la liste — aucune position
        #    publiée, aucun verdict transmis à Decision, alors que le lookup
        #    reconnaissait bien les IP Tor.
        anonymises = [v for v in verdicts
                      if str(getattr(getattr(v, "label", ""), "value",
                                     getattr(v, "label", ""))).lower()
                      in ("tor", "vpn")]
        self.counters["anonymized"] += len(anonymises)
        for v in anonymises:
            label = str(getattr(getattr(v, "label", ""), "value",
                                getattr(v, "label", ""))).lower()
            if label == "tor":
                self.counters["tor"] += 1
            elif label == "vpn":
                self.counters["vpn"] += 1

        self._publish(anonymises)
        self._forward(anonymises)
        return {"flows": len(flows), "anonymized": len(anonymises),
                "verdicts": len(verdicts)}

    def _publish(self, anonymises) -> None:
        """
        Publie les IP anonymisées comme positions à géolocaliser.

        ⚠️ Une position SANS coordonnées n'est pas affichable : la carte compte
        alors zéro position même si le bus a bien enregistré l'entrée. On
        demande donc au bus de géolocaliser l'IP (`/locate`) avant de publier.

        Si la base géographique est absente ou l'IP inconnue, la position est
        tout de même publiée : elle apparaît dans l'état et dans le compteur,
        sans marqueur sur la carte. Mieux vaut une IP signalée sans position
        qu'une IP passée sous silence — le Niveau 2 fera l'attribution.
        """
        try:
            vues = set()
            for v in anonymises:
                ip = getattr(v, "external_ip", None)
                if not ip or ip in vues:
                    continue          # une position par IP, pas par flux
                vues.add(ip)
                label = str(getattr(getattr(v, "label", ""), "value",
                                    getattr(v, "label", ""))).lower()

                position = {
                    "ip": ip, "ip_kind": label, "is_attacker": True,
                    # ⚠️ position_is_real=False pour une origine anonymisée.
                    #    La position obtenue est celle du RELAIS Tor/VPN, pas
                    #    de l'attaquant : la marquer « réelle » induirait en
                    #    erreur. C'est ce drapeau que le dashboard compte sous
                    #    « masquées », et qui distingue sur la carte un point
                    #    MASQUÉE d'un point RÉELLE.
                    "position_is_real": False,
                    "detail": f"relais {label} — origine réelle inconnue, "
                              f"attribution déléguée au Niveau 2",
                }
                geo = post_json(f"{BUS_URL}/locate", {"ip": ip}, timeout=10)
                if geo and geo.get("found"):
                    p = geo.get("position", {})
                    position.update({
                        "latitude": p.get("latitude"),
                        "longitude": p.get("longitude"),
                        "country": p.get("country"),
                        "city": p.get("city"),
                    })
                    print(f"[{AGENT_NAME}] {ip} ({label}) → "
                          f"{p.get('city') or '?'}, {p.get('country') or '?'}",
                          flush=True)
                else:
                    print(f"[{AGENT_NAME}] {ip} ({label}) — sans coordonnées "
                          f"(base géographique absente : déposer un .mmdb "
                          f"dans geo/)", flush=True)

                if post_json(f"{BUS_URL}/publish/position", position) is None:
                    print(f"[{AGENT_NAME}] position non publiée pour {ip}",
                          flush=True)
        except Exception as e:
            print(f"[{AGENT_NAME}] publication ignorée : {e}", flush=True)
        except Exception as e:
            print(f"[{AGENT_NAME}] publication ignorée : {e}", flush=True)

    def _forward(self, anonymises) -> None:
        """Transmet les verdicts d'anonymisation à Decision."""
        if not anonymises:
            return
        try:
            # Decision attend `label` et `external_ip` (cf. signal_normalizers)
            payload = {"anon_verdicts": [{
                "label": str(getattr(getattr(v, "label", ""), "value",
                                     getattr(v, "label", ""))).lower(),
                "external_ip": getattr(v, "external_ip", None),
                "confidence": float(getattr(v, "confidence", 0.0) or 0.0),
            } for v in anonymises], "source": AGENT_NAME}
        except Exception as e:
            print(f"[{AGENT_NAME}] sérialisation impossible : {e}", flush=True)
            return
        if post_json(f"{DECISION_URL}/ingest", payload) is None:
            print(f"[{AGENT_NAME}] Decision injoignable ({DECISION_URL}) — "
                  f"{len(anonymises)} verdict(s) non transmis", flush=True)

    def reset(self) -> dict:
        """
        Remet les compteurs et l'état interne à zéro.

        ⚠️ Nécessaire pour mesurer un run ISOLÉ. Sans cela, les compteurs
        cumulent depuis le démarrage du conteneur et les états rémanents
        (files d'attente, caches, fenêtres de corrélation) font déborder
        un run sur le suivant.
        """
        avant = dict(self.counters)
        for k in self.counters:
            self.counters[k] = 0
        return {"ok": True, "compteurs_avant": avant}

    def stats(self) -> dict:
        return {"agent": AGENT_NAME,
                "uptime_seconds": round(time.time() - self.started_at, 1),
                "counters": self.counters,
                "cascade": {"lookup": True,
                            "egraphsage": self.gnn is not None,
                            "anomale": self.anomale is not None},
                "bus_ready": self.bus_ready,
                "effort": (self.agentic.effort_report() if self.agentic else [])}


# -----------------------------------------------------------------------------
# Serveur HTTP
# -----------------------------------------------------------------------------
STATE: ServiceState | None = None


def _initialiser() -> None:
    """Construit l'état du service sans bloquer l'écoute HTTP."""
    global STATE
    STATE = ServiceState()
    print(f"[{AGENT_NAME}] initialisation terminée", flush=True)


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            # l'émetteur a fermé la connexion avant la réponse (délai dépassé
            # de son côté). Le traitement a eu lieu : inutile de polluer le
            # journal avec une trace complète.
            pass

    def do_GET(self):
        if self.path == "/health":
            if STATE is None:
                self._send(503, {"status": "initialisation", "agent": AGENT_NAME})
                return
            self._send(200, {"status": "ok", "agent": AGENT_NAME,
                             "egraphsage": STATE.gnn is not None,
                             "anomale": STATE.anomale is not None})
        elif self.path == "/stats":
            if STATE is None:
                self._send(503, {"status": "initialisation"})
                return
            self._send(200, STATE.stats())
        else:
            self._send(404, {"detail": "not found"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            self._send(400, {"detail": "JSON invalide"})
            return

        if STATE is None:
            self._send(503, {"detail": "service en cours d'initialisation"})
            return

        if self.path == "/handle":
            self._send(200, STATE.bus.handle_incoming(body))
        elif self.path == "/reset":
            if STATE is None:
                self._send(503, {"detail": "service en cours d'initialisation"})
            else:
                self._send(200, STATE.reset())
        elif self.path == "/ingest":
            items = body.get("flows") or body.get("items") or []
            if not isinstance(items, list):
                self._send(400, {"detail": "'flows' doit être une liste"})
                return
            self._send(200, {"ok": True,
                             **STATE.ingest(items, body.get("host_map"))})
        else:
            self._send(404, {"detail": "not found"})

    def log_message(self, *args):
        pass


def main() -> None:
    global STATE
    print(f"[{AGENT_NAME}] démarrage — bus={BUS_URL} port={PORT}", flush=True)
    # Le serveur écoute AVANT l'initialisation : l'attente du bus peut
    # durer jusqu'à 60 s, pendant lesquelles le HEALTHCHECK de
    # docker-compose déclarerait sinon le conteneur défaillant.
    # ⚠️ MULTI-THREAD OBLIGATOIRE. Un serveur mono-thread ne peut
    #    répondre à rien pendant qu'il traite une requête. Analysis
    #    attend Ollama des dizaines de secondes sur CPU : /health,
    #    /stats et surtout /handle (coopération inter-agents)
    #    devenaient injoignables — le bus affichait « agent
    #    injoignable » alors que l'agent fonctionnait.
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    threading.Thread(target=_initialiser, daemon=True).start()
    print(f"[{AGENT_NAME}] à l'écoute sur 0.0.0.0:{PORT}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"[{AGENT_NAME}] arrêt", flush=True)
        server.shutdown()


if __name__ == "__main__":
    main()
