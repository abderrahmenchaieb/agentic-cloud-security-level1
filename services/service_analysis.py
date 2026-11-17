"""
=============================================================================
SERVICE — AGENT ANALYSIS
=============================================================================
Point d'entrée exécutable de l'agent Analysis, destiné à son propre conteneur.

CE QUE FAIT CE SERVICE
    1. charge les détecteurs (Windows 18 features, Cloud 17 features)
    2. connecte Ollama pour l'interpréteur MITRE (optionnel)
    3. se connecte au bus — Analysis est ÉMETTEUR de requêtes (`check_gap` vers
       Collect), il n'enregistre aucun handler : rien ne lui est demandé
    4. expose :
         POST /ingest   ← Collect y pousse les logs enrichis (CanonicalLog)
         POST /handle   ← le bus y relaie les requêtes des autres agents
         GET  /health   ← sonde de santé
         GET  /stats    ← compteurs et décisions autonomes
    5. transmet les verdicts de menace à Decision

⚠️ CONVERSION CANONIQUE → EVENT
    Collect émet des `CanonicalLog` ; l'AnalysisAgent consomme des `Event`.
    La conversion passe par `windows_bridge`, qui préserve un point critique :
    `Event.event_id` doit porter l'EventID SYSMON (1, 3, 8…), pas l'UUID
    canonique — sinon toutes les features structurelles vaudraient zéro,
    silencieusement.

⚠️ ALIGNEMENT DES FEATURES
    Le détecteur est instancié avec `aligned_windows_features=True` : les
    18 features structurelles du modèle entraîné, et non les 14 features
    sémantiques historiques (qui supposaient des lignes de commande absentes
    de COMISET). Un seul nom était commun aux deux jeux.

⚠️ SCALER
    `inject_into_subdetector` installe un scaler IDENTITÉ : les RandomForest
    ont été entraînés sur features BRUTES. Appliquer une normalisation
    produirait des prédictions fausses sans aucune erreur visible.

VARIABLES D'ENVIRONNEMENT
    BUS_URL, AGENT_URL, DECISION_URL, MODELS_DIR, PORT
    OLLAMA_URL     URL d'Ollama            (défaut http://ollama:11434)
    OLLAMA_MODEL   modèle à utiliser       (défaut llama3.1)
    ENABLE_LLM     "0" pour désactiver l'interprétation
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
           os.path.join(_ROOT, "agents", "1_collect_agent"),
           os.path.join(_ROOT, "agents", "2_analysis_agent"),
           os.path.join(_ROOT, "agentic_layer"),
           os.path.join(_ROOT, "cloud_adapter")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from analysis_agent.analysis_agent import AnalysisAgent
from analysis_agent.unified_detector import UnifiedSequenceDetector
from agentic_layer.agent_bus_http import AgentBusHTTP
from agentic_layer.agentic_analysis import AgenticAnalysisAgent

BUS_URL      = os.environ.get("BUS_URL", "http://bus:8000")
AGENT_URL    = os.environ.get("AGENT_URL", "http://analysis:9002")
DECISION_URL = os.environ.get("DECISION_URL", "http://decision:9004")
MODELS_DIR   = os.environ.get("MODELS_DIR", os.path.join(_ROOT, "models"))
PORT         = int(os.environ.get("PORT", "9002"))
OLLAMA_URL   = os.environ.get("OLLAMA_URL", "http://ollama:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.1")
ENABLE_LLM   = os.environ.get("ENABLE_LLM", "1") == "1"

AGENT_NAME = "analysis"


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
# Client Ollama — implémente le protocole LLMClient (méthode `generate`)
# -----------------------------------------------------------------------------
class OllamaClient:
    """
    Client LLM minimal pour Ollama. Respecte le protocole attendu par
    `InterpretationEngine` : une seule méthode `generate(prompt) -> str`.
    """

    def __init__(self, base_url: str, model: str, timeout: float = 120.0):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def available(self) -> bool:
        import urllib.request
        try:
            with urllib.request.urlopen(f"{self.base_url}/api/tags",
                                        timeout=5) as r:
                return r.status == 200
        except Exception:
            return False

    def generate(self, prompt: str) -> str:
        res = post_json(f"{self.base_url}/api/generate", {
            "model": self.model, "prompt": prompt,
            "stream": False, "format": "json",
        }, self.timeout)
        if res is None:
            # Ollama indisponible : renvoyer une chaîne vide plutôt que lever.
            # L'interpréteur choisit alors parmi les candidats du RAG sans LLM,
            # et la DÉTECTION (le ML) reste pleinement fonctionnelle.
            return ""
        return res.get("response", "")


# -----------------------------------------------------------------------------
# Chargement des détecteurs
# -----------------------------------------------------------------------------
def build_detector():
    """
    Détecteur unifié avec les modèles entraînés injectés.
    Un modèle absent laisse sa voie non entraînée : l'autre continue de
    fonctionner (mode dégradé partiel plutôt que refus de démarrer).
    """
    sys.path.insert(0, _ROOT)
    from model_loader import load_sklearn_model, inject_into_subdetector

    det = UnifiedSequenceDetector(aligned_windows_features=True)
    charges = []
    for voie, sub, mdl, cfg in [
        ("windows", det._endpoint, "windows_detector.pkl", "windows_detector_config.pkl"),
        ("cloud",   det._cloud,    "cloud_detector.pkl",   "cloud_detector_config.pkl"),
    ]:
        p_mdl, p_cfg = os.path.join(MODELS_DIR, mdl), os.path.join(MODELS_DIR, cfg)
        if os.path.exists(p_mdl) and os.path.exists(p_cfg):
            try:
                inject_into_subdetector(sub, load_sklearn_model(p_mdl, p_cfg))
                charges.append(voie)
                print(f"[{AGENT_NAME}] détecteur {voie} chargé "
                      f"({len(sub._feature_names)} features)", flush=True)
            except Exception as e:
                print(f"[{AGENT_NAME}] échec du chargement {voie} : {e}", flush=True)
        else:
            print(f"[{AGENT_NAME}] modèle {voie} absent de {MODELS_DIR}", flush=True)
    return det, charges


def build_interpreter(llm):
    """Interpréteur MITRE (LLM + RAG). None si indisponible."""
    try:
        from analysis_agent.interpretation_engine import InterpretationEngine
        from analysis_agent.unified_mitre import build_unified_rag
        rag = build_unified_rag()
        print(f"[{AGENT_NAME}] RAG MITRE construit", flush=True)
        return InterpretationEngine(llm=llm, rag=rag)
    except Exception as e:
        print(f"[{AGENT_NAME}] interpréteur indisponible ({e}) — détection seule",
              flush=True)
        return None


# -----------------------------------------------------------------------------
# Reconstruction des Event depuis les CanonicalLog reçus de Collect
# -----------------------------------------------------------------------------
def logs_to_events(logs: list[dict]) -> tuple[list, list]:
    """
    Reconstruit des CanonicalLog depuis les dicts reçus, puis les convertit en
    Event — via le pont WINDOWS ou le pont CLOUD selon leur provenance.

    ⚠️ ROUTAGE PAR SOURCE
        Les deux voies n'ont ni les mêmes identifiants ni le même séquençage :

          Windows : Event.event_id = EventID Sysmon (1, 3, 8…)
                    séquences par process_guid
          Cloud   : pas de processus, mais une identité (userIdentity)
                    séquences par identité + fenêtre temporelle

        Tout convertir via le pont Windows produirait, pour le cloud, des
        événements sans process_guid : le séquenceur les regrouperait par hôte
        et le détecteur cloud (17 features) ne serait jamais sollicité.

    Renvoie (events_windows, events_cloud) — les deux listes sont analysées
    séparément, chacune par son détecteur.
    """
    from collect_agent.canonical_schema import CanonicalLog

    canoniques = []
    for d in logs:
        try:
            canoniques.append(CanonicalLog(**d))
        except Exception:
            continue  # log malformé : ignoré, le Collect l'a déjà tracé

    def _est_cloud(log) -> bool:
        st = getattr(log, "source_type", None)
        st = getattr(st, "value", st)
        if str(st or "").lower() == "cloud":
            return True
        # repli : un log cloud porte un contexte cloud, jamais de process_guid
        return getattr(log, "cloud_context", None) is not None

    cloud = [l for l in canoniques if _est_cloud(l)]
    windows = [l for l in canoniques if l not in cloud]

    events_win, events_cloud = [], []
    if windows:
        from analysis_agent.windows_bridge import canonical_to_windows_events
        events_win = canonical_to_windows_events(windows)
    if cloud:
        from cloud_adapter.cloud_sequence_builder import canonical_to_cloud_events
        events_cloud = canonical_to_cloud_events(cloud)
    return events_win, events_cloud


# -----------------------------------------------------------------------------
# État du service
# -----------------------------------------------------------------------------
class ServiceState:
    def __init__(self):
        self.detector, self.voies = build_detector()

        self.llm = OllamaClient(OLLAMA_URL, OLLAMA_MODEL) if ENABLE_LLM else None
        self.llm_ok = bool(self.llm and self.llm.available())
        if ENABLE_LLM and not self.llm_ok:
            print(f"[{AGENT_NAME}] Ollama injoignable ({OLLAMA_URL}) — "
                  f"détection active, interprétation MITRE désactivée", flush=True)
        elif self.llm_ok:
            print(f"[{AGENT_NAME}] Ollama connecté ({OLLAMA_MODEL})", flush=True)

        self.interpreter = build_interpreter(self.llm) if self.llm_ok else None
        self.analysis = AnalysisAgent(detector=self.detector,
                                      interpreter=self.interpreter)

        self.bus = AgentBusHTTP(bus_url=BUS_URL, agent_url=AGENT_URL,
                                agent_name=AGENT_NAME)
        # AgenticAnalysisAgent s'enregistre dans son constructeur : attendre le bus
        self.bus_ready = self._wait_for_bus()
        self.agentic = (AgenticAnalysisAgent(self.analysis, self.bus)
                        if self.bus_ready else None)
        print(f"[{AGENT_NAME}] " + ("coopération active" if self.bus_ready
                                    else "MODE DÉGRADÉ — bus injoignable"), flush=True)
        if self.bus_ready:
            self.enregistrer_handlers()
        # le registre du bus est en mémoire : se réinscrire s'il redémarre
        if self.bus_ready:
            self.bus.surveiller_enregistrement()

        self.attention: list = []      # IP signalées par Anonymization
        # ⚠️ Nombre d'analyses EN COURS. L'ingestion étant asynchrone (le
        #    traitement continue après la réponse HTTP), un observateur ne
        #    peut pas savoir si le système a fini en regardant les seuls
        #    compteurs : ils restent figés pendant qu'Ollama travaille.
        #    Ce compteur rend l'occupation OBSERVABLE.
        self.en_cours = 0
        self._verrou_en_cours = threading.Lock()
        # Séquences récemment analysées, pour permettre la réanalyse demandée
        # par Decision. Borné : sans limite, la mémoire croîtrait sans fin en
        # service continu.
        from collections import OrderedDict
        self.cache_sequences: "OrderedDict[str, list]" = OrderedDict()
        self.CACHE_MAX = 50
        self.counters = {"events": 0, "sequences": 0, "attacks": 0,
                         "interpreted": 0, "reanalyses": 0}
        self.started_at = time.time()

    def _wait_for_bus(self, retries: int = 30, delay: float = 2.0) -> bool:
        for i in range(retries):
            if self.bus.health():
                return True
            print(f"[{AGENT_NAME}] bus indisponible, tentative {i+1}/{retries}…",
                  flush=True)
            time.sleep(delay)
        return False

    # --- handlers de requêtes entrantes --------------------------------------
    def enregistrer_handlers(self) -> None:
        """
        Déclare ce qu'Analysis sait traiter.

        ⚠️ Sans ces enregistrements, les requêtes émises par les autres agents
        restent SANS DESTINATAIRE — le dashboard les affiche « unrouted, aucun
        handler ». Anonymization signale une IP suspecte (`attention_hint`) et
        Decision demande une réanalyse avant d'escalader (`reanalyze`) : deux
        canaux de coopération qui n'aboutissaient nulle part.
        """
        from agentic_layer.agent_bus import RequestType, AgentResponse

        def sur_attention_hint(req):
            """Anonymization a repéré une IP anonymisée sur un hôte."""
            ip = req.payload.get("ip") or req.payload.get("external_ip") or "?"
            hote = req.payload.get("host") or "?"
            label = req.payload.get("label") or "anonymisé"
            self.attention.append({"host": hote, "ip": ip, "label": label})
            print(f"[{AGENT_NAME}] attention signalée : {ip} ({label}) "
                  f"sur {hote}", flush=True)
            return AgentResponse(
                request_id=req.request_id, responder=AGENT_NAME, success=True,
                payload={"noted": True, "watchlist": len(self.attention)},
                detail=f"{ip} placée sous surveillance renforcée")

        def sur_reanalyze(req):
            """
            Decision demande une réanalyse avant de trancher.

            Les séquences récemment analysées sont conservées en cache : sans
            lui, Analysis traite en flux et ne peut rien rejouer — la
            re-sollicitation, pourtant prévue par la conception, resterait
            lettre morte.
            """
            cle = (req.payload.get("entity_key") or req.payload.get("host")
                   or req.payload.get("sequence_id") or "")
            self.counters["reanalyses"] += 1

            # Retrouver les événements. Decision identifie l'entité par un
            # `entity_key` qu'il génère lui-même (ex. « ent-a3991956 ») :
            # Analysis ne le connaît pas. On tente donc, dans l'ordre :
            #   1. la clé telle quelle (si c'est un sequence_id)
            #   2. l'hôte transmis dans la charge utile
            #   3. la séquence la plus récente, à défaut
            events = self.cache_sequences.get(cle)
            hote = req.payload.get("host")

            if events is None and hote:
                for sid, evts in reversed(list(self.cache_sequences.items())):
                    if evts and getattr(evts[0], "host", None) == hote:
                        events, cle = evts, sid
                        break

            if events is None and self.cache_sequences:
                # repli : la dernière séquence analysée. Decision demande une
                # réanalyse à chaud, c'est presque toujours la bonne.
                cle, events = next(reversed(self.cache_sequences.items()))

            if not events:
                return AgentResponse(
                    request_id=req.request_id, responder=AGENT_NAME, success=False,
                    payload={"entity_key": cle},
                    detail=f"séquence introuvable en cache "
                           f"({len(self.cache_sequences)} conservée(s))")

            # réanalyse effective, avec approfondissement
            outputs = self.analysis.analyze(events)
            verdicts = list(getattr(outputs, "verdicts", []) or [])
            attaques = [v for v in verdicts if getattr(v, "is_attack", False)]
            # ⚠️ NE PAS retransmettre le verdict à Decision.
            #    Decision a DEMANDÉ cette réanalyse : il reçoit le résultat
            #    dans la réponse ci-dessous. Le lui repousser via /ingest
            #    créerait une BOUCLE INFINIE — nouveau verdict en tampon,
            #    nouveau cycle de décision, nouvelle demande de réanalyse,
            #    et ainsi de suite : les compteurs d'attaques et d'échanges
            #    croissent sans fin même sans nouvelle injection.
            score = max((float(getattr(v, "attack_score", 0.0))
                         for v in verdicts), default=0.0)
            return AgentResponse(
                request_id=req.request_id, responder=AGENT_NAME, success=True,
                payload={"entity_key": cle, "n_events": len(events),
                         "attack_score": round(score, 3),
                         "is_attack": bool(attaques)},
                detail=f"réanalyse de {len(events)} événement(s) — "
                       f"score {score:.2f}"
                       + (" (attaque confirmée)" if attaques else " (normal)"))

        try:
            self.bus.register(RequestType.ATTENTION_HINT, sur_attention_hint,
                              AGENT_NAME)
            self.bus.register(RequestType.REANALYZE, sur_reanalyze, AGENT_NAME)
            print(f"[{AGENT_NAME}] enregistré : attention_hint, reanalyze",
                  flush=True)
        except Exception as e:
            print(f"[{AGENT_NAME}] enregistrement partiel : {e}", flush=True)

    # --- traitement -----------------------------------------------------------
    def ingest(self, logs: list[dict]) -> dict:
        """
        Accuse réception IMMÉDIATEMENT et traite en arrière-plan.

        ⚠️ POURQUOI CE DÉCOUPLAGE
            L'interprétation MITRE passe par Ollama, qui demande des dizaines
            de secondes sur CPU. En traitant dans le fil de la requête, Collect
            abandonnait au bout de son délai et Analysis écrivait sa réponse
            dans un socket fermé — `BrokenPipeError` en boucle, et des
            compteurs qui semblaient nuls alors que l'analyse était en cours.

            Dans un pipeline, l'ingestion doit accuser réception et rendre la
            main : l'émetteur n'a pas à attendre la fin du traitement.
        """
        events_win, events_cloud = logs_to_events(logs)
        total = len(events_win) + len(events_cloud)
        self.counters["events"] += total
        if not total:
            return {"events": 0, "queued": False}

        # les deux voies sont analysées séparément : chacune a son détecteur,
        # son séquençage et ses features
        with self._verrou_en_cours:
            self.en_cours += bool(events_win) + bool(events_cloud)
        if events_win:
            threading.Thread(target=self._traiter, args=(events_win, "windows"),
                             daemon=True).start()
        if events_cloud:
            threading.Thread(target=self._traiter, args=(events_cloud, "cloud"),
                             daemon=True).start()
        return {"events": total, "windows": len(events_win),
                "cloud": len(events_cloud), "queued": True}

    def _traiter(self, events, voie: str = "windows") -> None:
        """
        Analyse effective, hors du fil de la requête HTTP.

        `voie` sert au journal : le détecteur unifié route lui-même vers le
        sous-détecteur adéquat d'après la nature des événements.
        """
        try:
            processor = self.agentic if self.agentic is not None else self.analysis
            outputs = processor.analyze(events)

            verdicts = list(getattr(outputs, "verdicts", []) or [])
            attaques = [v for v in verdicts if getattr(v, "is_attack", False)]
            self._memoriser(verdicts, events)
            self.counters["sequences"] += len(verdicts)
            self.counters["attacks"] += len(attaques)
            # l'interprétation MITRE renseigne `techniques` (nom, tactique,
            # confiance) — il n'existe pas d'attribut `interpretation`
            self.counters["interpreted"] += sum(
                1 for v in verdicts if getattr(v, "techniques", None))

            self._publish(attaques)
            self._forward(attaques)
            if attaques:
                print(f"[{AGENT_NAME}] [{voie}] {len(verdicts)} séquence(s), "
                      f"{len(attaques)} attaque(s) → Decision", flush=True)
        except Exception as e:
            print(f"[{AGENT_NAME}] [{voie}] échec de l'analyse : {e}", flush=True)
        finally:
            with self._verrou_en_cours:
                self.en_cours = max(0, self.en_cours - 1)

    def _memoriser(self, verdicts, events) -> None:
        """
        Conserve les événements par séquence, pour une éventuelle réanalyse.
        Les plus anciens sont évincés au-delà de CACHE_MAX.
        """
        par_seq: dict[str, list] = {}
        for e in events:
            # un Event n'expose pas son sequence_id : on regroupe par
            # process_guid, qui est la clé de séquençage
            cle = getattr(e, "process_guid", None) or f"host:{getattr(e, 'host', '?')}"
            par_seq.setdefault(cle, []).append(e)

        for v in verdicts:
            sid = getattr(v, "sequence_id", None)
            if not sid:
                continue
            # rattacher les événements dont la clé correspond à la séquence
            evts = par_seq.get(sid) or (list(events) if len(par_seq) == 1 else [])
            if evts:
                self.cache_sequences[sid] = evts
        while len(self.cache_sequences) > self.CACHE_MAX:
            self.cache_sequences.popitem(last=False)

    def _publish(self, attaques) -> None:
        """
        Publie l'état des hôtes attaqués, pour le dashboard.

        ⚠️ NE PAS TOUCHER À `integrity_ok`.
            Ce champ appartient au Collect Agent : il traduit le résultat des
            règles forensiques (R1-R9) et de l'autoencodeur d'intégrité.
            Analysis n'analyse PAS l'intégrité des journaux — il n'a aucune
            information pour se prononcer dessus.

            Le renseigner à `True` écrasait le verdict du Collect au moment
            précis où l'attaque est confirmée : une machine dont les journaux
            avaient été falsifiés repassait « intègre » sur le dashboard, et
            l'information disparaissait quand elle compte le plus.

            En l'omettant, le bus conserve la valeur déjà connue.
        """
        for v in attaques:
            # ⚠️ Analysis signale une DÉTECTION, pas une attaque confirmée.
            #    Publier `security: under_attack` ici mettrait au même niveau
            #    un poste sain signalé par un faux positif du détecteur et une
            #    machine réellement compromise. Seul Decision connaît la
            #    certitude : c'est lui qui publiera l'état définitif
            #    (under_attack / under_investigation / monitored).
            post_json(f"{BUS_URL}/publish/host", {
                "host_id": getattr(v, "host", "unknown") or "unknown",
                "connection": "connected",
                "source_type": "endpoint",
                "detail": f"détection — menace {getattr(v, 'attack_score', 0):.2f}",
            })

    def _forward(self, attaques) -> None:
        """Transmet les verdicts de menace à Decision."""
        if not attaques:
            return
        post_json(f"{DECISION_URL}/ingest", {
            "threat_verdicts": [v.to_dict() if hasattr(v, "to_dict") else dict(v)
                                for v in attaques],
            "source": AGENT_NAME,
        })

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
        self.cache_sequences.clear()
        self.attention.clear()
        self.en_cours = 0
        return {"ok": True, "compteurs_avant": avant}

    def stats(self) -> dict:
        return {"agent": AGENT_NAME,
                "uptime_seconds": round(time.time() - self.started_at, 1),
                "counters": self.counters,
                "detectors": self.voies,
                "llm": {"enabled": ENABLE_LLM, "connected": self.llm_ok,
                        "model": OLLAMA_MODEL},
                "en_cours": self.en_cours,     # analyses non terminées
                "bus_ready": self.bus_ready,
                "attention": self.attention[-5:],
                "cache_sequences": len(self.cache_sequences),
                "decisions": (self.agentic.decisions_report()
                              if self.agentic else [])}


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
                             "detectors": STATE.voies, "llm": STATE.llm_ok})
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
            logs = body.get("enriched") or body.get("logs") or []
            if not isinstance(logs, list):
                self._send(400, {"detail": "'enriched' doit être une liste"})
                return
            self._send(200, {"ok": True, **STATE.ingest(logs)})
        else:
            self._send(404, {"detail": "not found"})

    def log_message(self, *args):
        pass


def main() -> None:
    global STATE
    print(f"[{AGENT_NAME}] démarrage — bus={BUS_URL} port={PORT} "
          f"ollama={OLLAMA_URL}", flush=True)
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
