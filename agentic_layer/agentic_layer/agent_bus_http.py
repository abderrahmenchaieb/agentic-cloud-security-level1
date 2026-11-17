"""
=============================================================================
BUS DE REQUÊTES INTER-AGENTS — VERSION RÉSEAU (HTTP)
=============================================================================
Remplaçant réseau de `AgentBus` (en mémoire), pour le déploiement en
conteneurs séparés.

POURQUOI
    `AgentBus` route les requêtes via un dictionnaire de fonctions Python
    partagé en mémoire. Cela suppose que TOUS les agents vivent dans le MÊME
    processus. Dès qu'on isole chaque agent dans son conteneur, ce partage
    disparaît : les requêtes ne trouvent plus de handler et la coopération
    inter-agents s'arrête — silencieusement.

    Le code d'origine l'avait anticipé : « Bus EN MÉMOIRE (synchrone) […]
    remplaçable par une vraie file (Redis, Kafka…) sans changer le code des
    agents (même interface). » Ce module est ce remplacement.

MODÈLE — registre de services (inversion du routage)
    En mémoire, le bus APPELLE une fonction locale. En réseau, il ne peut pas :
    chaque agent est un processus distinct. Le modèle s'inverse donc —

        1. l'agent expose un endpoint HTTP  POST /handle
        2. il s'enregistre auprès du bus    POST /register {type, url, nom}
        3. le bus route en RELAYANT la requête vers l'URL enregistrée

    Le bus devient un routeur de messages, non un exécuteur de fonctions.

INTERFACE — strictement identique à `AgentBus`
    `register()`, `request()`, `interactions()`, `count_by_type()`.
    Le code des agents n'a pas à changer : seule l'instanciation diffère.

        # en mémoire (tests, mono-processus)
        bus = AgentBus()
        # en réseau (conteneurs)
        bus = AgentBusHTTP(bus_url="http://bus:8000", agent_url="http://collect:9001")

BÉNÉFICE POUR LA DÉMONSTRATION
    Chaque échange devient un appel HTTP réel, tracé par le bus et poussé au
    dashboard via WebSocket : la coopération inter-agents devient observable.
=============================================================================
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Callable, Optional

from .agent_bus import (
    AgentRequest, AgentResponse, BusLogEntry, RequestType,
)

DEFAULT_TIMEOUT = 10.0


def _post(url: str, payload: dict, timeout: float = DEFAULT_TIMEOUT) -> Optional[dict]:
    """POST JSON minimaliste (sans dépendance externe : urllib suffit)."""
    data = json.dumps(payload, default=str).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body) if body else {}
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
        return None


class AgentBusHTTP:
    """
    Bus inter-agents distribué. Même interface que `AgentBus`, mais les
    requêtes transitent par le bus réseau au lieu de la mémoire partagée.

    bus_url    : URL du bus central (ex. http://bus:8000)
    agent_url  : URL de CET agent, telle que le bus doit le joindre
                 (ex. http://collect:9001). Requise pour `register()`.
    agent_name : nom de l'agent, utilisé dans les traces.
    """

    def __init__(self, bus_url: str, agent_url: str = "", agent_name: str = "",
                 timeout: float = DEFAULT_TIMEOUT):
        self.bus_url = bus_url.rstrip("/")
        self.agent_url = agent_url.rstrip("/")
        self.agent_name = agent_name
        self.timeout = timeout
        # handlers locaux : appelés quand le bus relaie une requête à CET agent
        self._handlers: dict[RequestType, Callable[[AgentRequest], AgentResponse]] = {}
        # journal local (le bus tient le journal global)
        self.log: list[BusLogEntry] = []

    # ------------------------------------------------------------------
    # Enregistrement
    # ------------------------------------------------------------------
    def register(self, request_type: RequestType,
                 handler: Callable[[AgentRequest], AgentResponse],
                 agent_name: str = "") -> None:
        """
        Déclare que cet agent sait traiter ce type de requête.
        Conserve le handler localement ET signale l'URL de l'agent au bus.
        """
        if request_type in self._handlers:
            raise ValueError(f"Un handler existe déjà pour {request_type.value} "
                             f"(tentative par {agent_name or self.agent_name}).")
        self._handlers[request_type] = handler

        if not self.agent_url:
            raise ValueError(
                "agent_url est requise pour l'enregistrement réseau : le bus doit "
                "savoir à quelle adresse relayer les requêtes de ce type.")

        res = _post(f"{self.bus_url}/register", {
            "request_type": request_type.value,
            "agent_url": f"{self.agent_url}/handle",
            "agent_name": agent_name or self.agent_name,
        }, self.timeout)
        if res is None:
            raise ConnectionError(
                f"Enregistrement impossible auprès du bus ({self.bus_url}). "
                f"Le bus est-il démarré et joignable depuis ce conteneur ?")
        self._nom_enregistre = agent_name or self.agent_name

    def reenregistrer(self) -> int:
        """
        Réinscrit tous les handlers auprès du bus.

        ⚠️ INDISPENSABLE — le registre du bus est EN MÉMOIRE. S'il redémarre
        (reconstruction du conteneur, plantage), il oublie tous les agents.
        Ceux-ci continuent de tourner en se croyant inscrits, mais le bus ne
        les connaît plus : la coopération s'arrête SILENCIEUSEMENT, et le
        dashboard n'affiche plus que « aucun handler ».

        Renvoie le nombre de handlers réinscrits.
        """
        n = 0
        for rtype in self._handlers:
            res = _post(f"{self.bus_url}/register", {
                "request_type": rtype.value,
                "agent_url": f"{self.agent_url}/handle",
                "agent_name": getattr(self, "_nom_enregistre", self.agent_name),
            }, self.timeout)
            if res is not None:
                n += 1
        return n

    def surveiller_enregistrement(self, intervalle: int = 30) -> None:
        """
        Vérifie périodiquement que le bus connaît toujours cet agent, et se
        réinscrit sinon. À lancer dans un fil dédié.
        """
        import json as _json
        import threading

        def boucle():
            while True:
                time.sleep(intervalle)
                if not self._handlers:
                    continue
                try:
                    with urllib.request.urlopen(
                            f"{self.bus_url}/registry", timeout=5) as r:
                        connus = _json.load(r).get("remote_handlers", {})
                    manquants = [t.value for t in self._handlers
                                 if t.value not in connus]
                    if manquants:
                        n = self.reenregistrer()
                        print(f"[{self.agent_name}] bus redémarré — "
                              f"{n} handler(s) réinscrit(s)", flush=True)
                except Exception:
                    pass   # bus injoignable : on réessaiera au prochain tour

        threading.Thread(target=boucle, daemon=True).start()

    # ------------------------------------------------------------------
    # Émission d'une requête
    # ------------------------------------------------------------------
    def request(self, request: AgentRequest) -> Optional[AgentResponse]:
        """
        Poste une requête sur le bus, qui la relaie à l'agent enregistré.
        Renvoie la réponse, ou None si personne ne gère ce type — comportement
        identique à la version en mémoire.
        """
        res = _post(f"{self.bus_url}/request", {
            "sender": request.sender or self.agent_name,
            "target": "",                       # le bus résout la cible
            "request_type": request.request_type.value,
            "payload": request.payload,
        }, self.timeout)

        if res is None or not res.get("success", False):
            # bus injoignable, ou aucun handler enregistré pour ce type
            self.log.append(BusLogEntry(request=request, response=None, handled=False))
            return None

        response = AgentResponse(
            request_id=request.request_id,
            responder=res.get("responder", "unknown"),
            success=bool(res.get("success", False)),
            payload=res.get("payload", {}) or {},
            detail=res.get("detail", ""),
        )
        self.log.append(BusLogEntry(request=request, response=response, handled=True))
        return response

    # ------------------------------------------------------------------
    # Réception (côté serveur de l'agent)
    # ------------------------------------------------------------------
    def handle_incoming(self, body: dict) -> dict:
        """
        Traite une requête relayée par le bus. À brancher sur l'endpoint
        `POST /handle` du serveur de l'agent.
        """
        try:
            rtype = RequestType(body.get("request_type"))
        except ValueError:
            return {"success": False, "responder": self.agent_name,
                    "payload": {}, "detail": f"type inconnu : {body.get('request_type')}"}

        handler = self._handlers.get(rtype)
        if handler is None:
            return {"success": False, "responder": self.agent_name, "payload": {},
                    "detail": f"cet agent ne traite pas {rtype.value}"}

        req = AgentRequest(request_type=rtype,
                           sender=body.get("sender", "?"),
                           payload=body.get("payload", {}) or {})
        resp = handler(req)
        self.log.append(BusLogEntry(request=req, response=resp, handled=True))
        return {"success": resp.success, "responder": resp.responder or self.agent_name,
                "payload": resp.payload, "detail": resp.detail}

    # ------------------------------------------------------------------
    # Traçabilité — identique à AgentBus
    # ------------------------------------------------------------------
    def interactions(self) -> list[dict]:
        """Échanges vus par CET agent. Le journal global est tenu par le bus."""
        out = []
        for entry in self.log:
            r, resp = entry.request, entry.response
            out.append({
                "type": r.request_type.value,
                "from": r.sender,
                "to": resp.responder if resp else "(personne)",
                "success": resp.success if resp else False,
                "detail": resp.detail if resp else "non traité",
            })
        return out

    def count_by_type(self) -> dict:
        from collections import Counter
        return dict(Counter(e.request.request_type.value for e in self.log))

    # ------------------------------------------------------------------
    def health(self) -> bool:
        """Le bus est-il joignable ? Utile au démarrage d'un conteneur."""
        try:
            with urllib.request.urlopen(f"{self.bus_url}/health", timeout=3) as r:
                return r.status == 200
        except Exception:
            return False
