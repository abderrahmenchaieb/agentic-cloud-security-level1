"""
=============================================================================
SERVICE — AGENT COLLECT
=============================================================================
Point d'entrée exécutable de l'agent Collect, destiné à tourner dans son
propre conteneur. C'est ce que lance le Dockerfile.

CE QUE FAIT CE SERVICE
    1. charge l'autoencodeur d'intégrité (Windows et/ou cloud)
    2. instancie CollectAgent + AgenticCollectAgent
    3. s'enregistre auprès du bus comme handler de `check_gap` et `recollect`
    4. expose :
         POST /ingest   ← le forwarder Windows y pousse les logs Sysmon bruts
         POST /handle   ← le bus y relaie les requêtes des autres agents
         GET  /health   ← sonde de santé (docker-compose, diagnostic)
         GET  /stats    ← compteurs de traitement et vigilance
    5. traite, puis transmet les sorties à Analysis et publie l'état au bus

VARIABLES D'ENVIRONNEMENT
    BUS_URL        URL du bus              (défaut http://bus:8000)
    AGENT_URL      URL de CET agent        (défaut http://collect:9001)
    ANALYSIS_URL   URL de l'agent Analysis (défaut http://analysis:9002)
    MODELS_DIR     dossier des modèles     (défaut /app/models)
    PORT           port d'écoute           (défaut 9001)
    REPLAY_MODE    "1" pour rejouer des logs historiques (voir plus bas)

⚠️ REPLAY_MODE
    En temps réel, `ingest_time` vaut l'instant d'ingestion, et l'écart avec
    `event_time` mesure une vraie dérive d'horloge (règle R3). Sur un dataset
    rejoué des années plus tard, cet écart atteint des centaines de jours et
    R3_clock_skew se déclenche sur CHAQUE événement. Mettre REPLAY_MODE=1
    quand on rejoue un corpus historique ; le laisser à 0 en production.
=============================================================================
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# --- chemins (le conteneur monte le système sous /app) -----------------------
_ROOT = os.environ.get("SYSTEM_ROOT", os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
for _p in (_ROOT,
           os.path.join(_ROOT, "agents", "1_collect_agent"),
           os.path.join(_ROOT, "agentic_layer")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from collect_agent.collect_agent import CollectAgent
from agentic_layer.agent_bus import RequestType
from agentic_layer.agent_bus_http import AgentBusHTTP
from agentic_layer.agentic_collect import AgenticCollectAgent

BUS_URL      = os.environ.get("BUS_URL", "http://bus:8000")
AGENT_URL    = os.environ.get("AGENT_URL", "http://collect:9001")
ANALYSIS_URL = os.environ.get("ANALYSIS_URL", "http://analysis:9002")
ANON_URL     = os.environ.get("ANON_URL", "http://anonymization:9003")
DECISION_URL = os.environ.get("DECISION_URL", "http://decision:9004")
MODELS_DIR   = os.environ.get("MODELS_DIR", os.path.join(_ROOT, "models"))
PORT         = int(os.environ.get("PORT", "9001"))
REPLAY_MODE  = os.environ.get("REPLAY_MODE", "0") == "1"

AGENT_NAME = "collect"


# -----------------------------------------------------------------------------
# Utilitaire HTTP (urllib suffit : pas de dépendance supplémentaire)
# -----------------------------------------------------------------------------
def post_json(url: str, payload: dict, timeout: float = 10.0):
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
# Chargement des modèles — échec NON bloquant
# -----------------------------------------------------------------------------
def load_autoencoders() -> dict:
    """
    Charge les autoencodeurs d'intégrité disponibles.

    Un modèle absent n'empêche PAS le démarrage : les règles forensiques R1-R9
    fonctionnent sans lui, et l'agent doit rester opérationnel en mode dégradé
    plutôt que refuser de démarrer.
    """
    loaded = {}
    try:
        sys.path.insert(0, _ROOT)
        from model_loader import load_collect_autoencoder
    except Exception as e:
        print(f"[{AGENT_NAME}] model_loader indisponible ({e}) — règles seules", flush=True)
        return loaded

    for monde, mdl, cfg in [
        ("windows", "collect_autoencoder_final.pt", "collect_autoencoder_final_config.pkl"),
        ("cloud",   "collect_cloud_ae_final.pt",    "collect_cloud_ae_final_config.pkl"),
    ]:
        p_mdl, p_cfg = os.path.join(MODELS_DIR, mdl), os.path.join(MODELS_DIR, cfg)
        if os.path.exists(p_mdl) and os.path.exists(p_cfg):
            try:
                ae = load_collect_autoencoder(p_mdl, p_cfg)
                loaded[monde] = ae
                print(f"[{AGENT_NAME}] autoencodeur {monde} chargé "
                      f"({len(ae.score_names)} scores, W={ae.window_size}, "
                      f"seuil {ae.seuil:.4f})", flush=True)
            except Exception as e:
                print(f"[{AGENT_NAME}] échec du chargement {monde} : {e}", flush=True)
        else:
            print(f"[{AGENT_NAME}] modèle {monde} absent de {MODELS_DIR}", flush=True)
    return loaded


# -----------------------------------------------------------------------------
# État du service
# -----------------------------------------------------------------------------
class ServiceState:
    def __init__(self):
        self.autoencoders = load_autoencoders()
        self.collect = CollectAgent(replay_mode=REPLAY_MODE)
        self.bus = AgentBusHTTP(bus_url=BUS_URL, agent_url=AGENT_URL,
                                agent_name=AGENT_NAME)
        # ⚠️ AgenticCollectAgent s'enregistre auprès du bus DANS son
        # constructeur : il faut donc que le bus soit joignable AVANT de
        # l'instancier. docker-compose ne garantit pas l'ordre de démarrage
        # (`depends_on` attend le conteneur, pas le service prêt), d'où
        # l'attente active ci-dessous.
        self.bus_ready = self._wait_for_bus()
        self.agentic = AgenticCollectAgent(self.collect, self.bus) if self.bus_ready else None
        # le registre du bus est en mémoire : se réinscrire s'il redémarre
        if self.bus_ready:
            self.bus.surveiller_enregistrement()
        if self.bus_ready:
            print(f"[{AGENT_NAME}] enregistré : check_gap, recollect", flush=True)
        else:
            print(f"[{AGENT_NAME}] MODE DÉGRADÉ — bus injoignable : traitement "
                  f"assuré, coopération inter-agents indisponible", flush=True)
        # lots en attente de retransmission (destinataire indisponible)
        self.attente_analysis: list = []
        self.attente_anon: list = []
        self.counters = {"received": 0, "enriched": 0, "flows": 0,
                         "gaps": 0, "rejected": 0, "integrity_alerts": 0,
                         "reessais": 0, "perdus": 0}
        self.started_at = time.time()

    def _wait_for_bus(self, retries: int = 30, delay: float = 2.0) -> bool:
        """Attend que le bus réponde. Ne bloque pas indéfiniment."""
        for i in range(retries):
            if self.bus.health():
                return True
            print(f"[{AGENT_NAME}] bus indisponible, tentative {i+1}/{retries}…",
                  flush=True)
            time.sleep(delay)
        return False

    # --- traitement d'un lot de logs bruts -----------------------------------
    def ingest(self, raws: list[dict], source: str = "") -> dict:
        self.counters["received"] += len(raws)

        # ⚠️ CollectAgent.outputs ACCUMULE sans jamais se vider : conçu pour un
        # traitement en une passe (tests, rejeu d'un corpus). En service
        # continu, chaque lot renverrait tout l'historique — Analysis recevrait
        # les mêmes logs en boucle et la mémoire croîtrait indéfiniment.
        # On repart donc d'une sortie vierge à chaque lot.
        from collect_agent.collect_agent import CollectOutputs
        self.collect.outputs = CollectOutputs()

        # ⚠️ ROUTAGE PAR SOURCE — Sysmon et CloudTrail n'ont RIEN en commun.
        #    Le mapper Sysmon attend « EventID », « UtcTime », « ProcessGuid » ;
        #    un événement CloudTrail porte « eventName », « eventTime »,
        #    « userIdentity ». Le passer au mapper Sysmon le ferait rejeter
        #    comme malformé — la voie cloud serait silencieusement inopérante.
        if self._est_cloudtrail(raws, source):
            outputs = self._ingest_cloud(raws)
        else:
            # en mode dégradé (bus injoignable), on traite avec l'agent nu :
            # les règles R1-R9 et l'autoencodeur fonctionnent sans coopération
            processor = self.agentic if self.agentic is not None else self.collect
            outputs = processor.process_batch(raws)

        self.counters["enriched"] += len(outputs.enriched)
        self.counters["flows"]    += len(outputs.flows)
        self.counters["gaps"]     += len(outputs.gaps)
        self.counters["rejected"] += len(outputs.rejected)
        alertes = sum(1 for e in outputs.enriched if e.has_integrity_issue)
        self.counters["integrity_alerts"] += alertes

        self._publish_hosts(outputs)
        self._forward(outputs)
        return {"enriched": len(outputs.enriched), "flows": len(outputs.flows),
                "gaps": len(outputs.gaps), "rejected": len(outputs.rejected),
                "integrity_alerts": alertes}

    @staticmethod
    def _est_cloudtrail(raws: list[dict], source: str) -> bool:
        """Reconnaît un lot CloudTrail : source déclarée ou champs natifs."""
        if "cloud" in (source or "").lower():
            return True
        return bool(raws) and isinstance(raws[0], dict) and (
            "eventSource" in raws[0] or "userIdentity" in raws[0])

    def _ingest_cloud(self, raws: list[dict]):
        """
        Traite un lot CloudTrail via l'adaptateur dédié (pattern adaptateur).
        L'adaptateur produit des CanonicalLog, que le Collect enrichit ensuite
        exactement comme ceux issus de Sysmon — c'est tout l'intérêt du schéma
        canonique unifié.
        """
        # ⚠️ Import DIRECT des modules, sans passer par `cloud_adapter/__init__`
        #    qui importe le séquenceur cloud — lequel dépend d'`analysis_agent`,
        #    absent de ce conteneur. Le Collect n'a besoin que de l'adaptateur
        #    et du pont vers ses propres sorties.
        import importlib, json as _json
        _ad = importlib.import_module("cloud_adapter.cloud_adapter")
        _pont = importlib.import_module("cloud_adapter.cloud_to_collect")
        AwsCloudTrailAdapter = _ad.AwsCloudTrailAdapter
        process_canonical_logs = _pont.process_canonical_logs

        adaptateur = AwsCloudTrailAdapter(replay_mode=REPLAY_MODE)
        logs = adaptateur.parse(_json.dumps({"Records": raws}))
        print(f"[{AGENT_NAME}] lot CloudTrail : {len(logs)}/{len(raws)} "
              f"canoniques", flush=True)
        return process_canonical_logs(self.collect, logs)

    def _publish_hosts(self, outputs) -> None:
        """
        Publie l'état des hôtes vus, pour le dashboard.
        Isolé : un bus indisponible ne doit jamais faire échouer l'ingestion.
        """
        try:
            self._publish_hosts_inner(outputs)
        except Exception as e:
            print(f"[{AGENT_NAME}] publication d'état ignorée : {e}", flush=True)

    def _publish_hosts_inner(self, outputs) -> None:
        hosts: dict[str, bool] = {}
        for e in outputs.enriched:
            h = getattr(e.log, "host", None) or "unknown"
            hosts[h] = hosts.get(h, True) and not e.has_integrity_issue
        for host, integre in hosts.items():
            post_json(f"{BUS_URL}/publish/host", {
                "host_id": host, "connection": "connected",
                "security": "normal", "integrity_ok": integre,
                "source_type": "endpoint",
                "event_count": self.counters["received"],
                "detail": "" if integre else "anomalie d'intégrité signalée",
            })

    def _forward(self, outputs) -> None:
        """
        Transmet les sorties à leurs destinataires :
          enriched + gaps → Analysis        (détection de menace)
          flows           → Anonymization   (détection VPN/Tor)

        ⚠️ Les DEUX routages sont nécessaires. Sans le second, les flux
        extraits restent sans destinataire : l'agent Anonymization ne reçoit
        rien, ne détecte aucun Tor et ne publie aucune position — la carte du
        dashboard reste vide alors que le trafic anonymisé a bien été vu.

        Isolé : un destinataire indisponible ne doit pas interrompre le
        traitement, le Collect a déjà fait son travail.
        """
        # --- vers Analysis : logs enrichis et signalements de trous ---
        if outputs.enriched or outputs.gaps:
            try:
                payload = {
                    "enriched": [_serialize_log(e.log) for e in outputs.enriched],
                    "gaps": [str(g) for g in outputs.gaps],
                    "source": AGENT_NAME,
                }
            except Exception as e:
                print(f"[{AGENT_NAME}] sérialisation impossible : {e}", flush=True)
                payload = None
            if payload and post_json(f"{ANALYSIS_URL}/ingest", payload) is None:
                # ⚠️ NE PAS ABANDONNER LES DONNÉES.
                #    Analysis peut être en cours d'initialisation (il répond
                #    alors 503) ou redémarrer. Jeter le lot ferait disparaître
                #    silencieusement des logs déjà traités — inacceptable pour
                #    un agent dont le rôle est justement l'intégrité.
                self.attente_analysis.append(payload)
                print(f"[{AGENT_NAME}] Analysis indisponible — "
                      f"{len(outputs.enriched)} log(s) mis en attente "
                      f"({len(self.attente_analysis)} lot(s) en file)", flush=True)

        # --- vers Decision : signaux d'intégrité ---
        # ⚠️ RELATION MANQUANTE JUSQU'ICI.
        #    Le Collect détectait les falsifications (règles R1-R9,
        #    autoencodeur) mais ne les transmettait à PERSONNE. Decision
        #    recevait donc `integrity_flags: 0` alors que des traces
        #    d'effacement avaient été relevées — et le dossier transmis au
        #    Niveau 2 partait avec `integrity_context: []`.
        #
        #    C'est pourtant le signal le plus discriminant du modèle
        #    décisionnel : la falsification agit comme CONFIRMATEUR (une
        #    menace modérée + une falsification devient une menace confirmée).
        #    Sans lui, la règle R2 ne pouvait jamais se déclencher.
        flags = []
        for e in outputs.enriched:
            if not e.has_integrity_issue:
                continue
            hote = getattr(e.log, "host", None) or "unknown"
            for a in (getattr(e, "annotations", None) or []):
                # `confidence` vaut "high" pour une règle forensique (R1-R9),
                # "medium" pour une détection de l'autoencodeur : on la traduit
                # en sévérité numérique, que le normalizer attend.
                severite = 0.9 if getattr(a, "confidence", "") == "high" else 0.7
                flags.append([hote,
                              f"{getattr(a, 'kind', '?')}: {getattr(a, 'detail', '')}",
                              severite])
        for g in outputs.gaps:
            # `source_key` est au format "host:provider"
            hote = str(getattr(g, "source_key", "") or "unknown").split(":")[0]
            flags.append([hote or "unknown",
                          f"gap: {getattr(g, 'detail', '')}",
                          float(getattr(g, "severity_score", 0.7) or 0.7)])

        if flags:
            if post_json(f"{DECISION_URL}/ingest",
                         {"integrity_flags": flags, "source": AGENT_NAME}) is None:
                print(f"[{AGENT_NAME}] Decision injoignable ({DECISION_URL}) — "
                      f"{len(flags)} signal(aux) d'intégrité non transmis", flush=True)

        # --- vers Anonymization : flux réseau ---
        if outputs.flows:
            try:
                flux = [_serialize_flow(f) for f in outputs.flows]
            except Exception as e:
                print(f"[{AGENT_NAME}] sérialisation des flux impossible : {e}",
                      flush=True)
                return
            if post_json(f"{ANON_URL}/ingest",
                         {"flows": flux, "source": AGENT_NAME}) is None:
                self.attente_anon.append({"flows": flux, "source": AGENT_NAME})
                print(f"[{AGENT_NAME}] Anonymization indisponible — "
                      f"{len(flux)} flux mis en attente", flush=True)

    def rejouer_attente(self) -> None:
        """
        Retransmet les lots mis en attente. Appelée périodiquement : un
        destinataire indisponible finit par revenir (fin d'initialisation,
        redémarrage). Un lot n'est abandonné qu'après MAX_REESSAIS tentatives,
        et l'abandon est alors compté — jamais silencieux.
        """
        MAX_EN_FILE = 100      # borne mémoire : au-delà, on perd les plus vieux
        for file, url, nom in ((self.attente_analysis, f"{ANALYSIS_URL}/ingest", "Analysis"),
                               (self.attente_anon, f"{ANON_URL}/ingest", "Anonymization")):
            if not file:
                continue
            if len(file) > MAX_EN_FILE:
                perdus = len(file) - MAX_EN_FILE
                del file[:perdus]
                self.counters["perdus"] += perdus
                print(f"[{AGENT_NAME}] file {nom} saturée — {perdus} lot(s) "
                      f"abandonné(s)", flush=True)
            restants = []
            for lot in file:
                if post_json(url, lot) is None:
                    restants.append(lot)
                else:
                    self.counters["reessais"] += 1
            file[:] = restants
            if not file and self.counters["reessais"]:
                print(f"[{AGENT_NAME}] file {nom} vidée", flush=True)

    def boucle_reessai(self, intervalle: int = 15) -> None:
        while True:
            time.sleep(intervalle)
            try:
                self.rejouer_attente()
            except Exception as e:
                print(f"[{AGENT_NAME}] réessai : {e}", flush=True)

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
        self.attente_analysis.clear()
        self.attente_anon.clear()
        return {"ok": True, "compteurs_avant": avant}

    def stats(self) -> dict:
        return {"agent": AGENT_NAME,
                "uptime_seconds": round(time.time() - self.started_at, 1),
                "counters": self.counters,
                "autoencoders": sorted(self.autoencoders.keys()),
                "replay_mode": REPLAY_MODE,
                "en_attente": {"analysis": len(self.attente_analysis),
                               "anonymization": len(self.attente_anon)},
                "bus_ready": self.bus_ready,
                "vigilance": self.agentic.vigilance_report() if self.agentic else {}}


def _serialize_flow(flow) -> dict:
    """
    FlowRecord → dict attendu par l'agent Anonymization.

    Le Collect ne produit PAS de statistiques de flux (durée, tailles de
    paquets, IAT) : un événement Sysmon EventID 3 ne les contient pas. Seul
    l'étage LOOKUP de la cascade pourra donc travailler — reconnaître une IP
    Tor ou VPN connue. Les 76 features d'E-GraphSAGE exigent une capture
    réseau traitée par CICFlowMeter (voir services/sonde_windows.py).
    """
    return {
        "flow_id": getattr(flow, "event_id", "") or "",
        "src_ip": getattr(flow, "source_ip", None) or "",
        "dst_ip": getattr(flow, "destination_ip", None) or "",
        "dst_port": getattr(flow, "destination_port", None),
        "protocol": getattr(flow, "protocol", None) or "",
        "timestamp": getattr(flow, "event_time", "") or "",
        "features": {},          # aucune statistique disponible depuis Sysmon
    }


def _serialize_log(log) -> dict:
    """CanonicalLog → dict transmissible en JSON."""
    if hasattr(log, "model_dump"):
        return json.loads(log.model_dump_json())
    if hasattr(log, "dict"):
        return json.loads(json.dumps(log.dict(), default=str))
    return json.loads(json.dumps(log, default=str))


# -----------------------------------------------------------------------------
# Serveur HTTP
# -----------------------------------------------------------------------------
STATE: ServiceState | None = None


def _initialiser() -> None:
    """Construit l'état du service (modèles, bus) sans bloquer l'écoute HTTP."""
    global STATE
    STATE = ServiceState()
    threading.Thread(target=STATE.boucle_reessai, daemon=True).start()
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
                # le service écoute mais n'est pas encore prêt
                self._send(503, {"status": "initialisation", "agent": AGENT_NAME})
            else:
                self._send(200, {"status": "ok", "agent": AGENT_NAME,
                                 "models": sorted(STATE.autoencoders.keys())})
        elif self.path == "/stats":
            if STATE is None:
                self._send(503, {"status": "initialisation"})
            else:
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

        if self.path == "/handle":
            # requête relayée par le bus (check_gap, recollect)
            self._send(200, STATE.bus.handle_incoming(body))
        elif self.path == "/reset":
            if STATE is None:
                self._send(503, {"detail": "service en cours d'initialisation"})
            else:
                self._send(200, STATE.reset())
        elif self.path == "/ingest":
            raws = body.get("events") or body.get("raws") or []
            if not isinstance(raws, list):
                self._send(400, {"detail": "'events' doit être une liste"})
                return
            self._send(200, {"ok": True,
                             **STATE.ingest(raws, body.get("source", ""))})
        else:
            self._send(404, {"detail": "not found"})

    def log_message(self, *args):
        pass  # journalisation silencieuse (les compteurs suffisent)


def main() -> None:
    global STATE
    print(f"[{AGENT_NAME}] démarrage — bus={BUS_URL} port={PORT} "
          f"replay={REPLAY_MODE}", flush=True)

    # ⚠️ Le serveur HTTP doit écouter AVANT l'initialisation complète.
    #    L'attente du bus peut durer jusqu'à 60 s ; si le port n'était ouvert
    #    qu'après, /health resterait injoignable tout ce temps et le
    #    HEALTHCHECK de docker-compose déclarerait le conteneur défaillant.
    #    On initialise donc en arrière-plan : le service répond immédiatement
    #    « en cours d'initialisation », puis « ok » une fois prêt.
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
