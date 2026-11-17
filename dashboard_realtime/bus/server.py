# =============================================================================
# BUS RÉSEAU — service central (FastAPI + WebSocket)
# =============================================================================
# Version RÉSEAU du bus agentique. Trois rôles :
#   1. ROUTER les requêtes inter-agents (check_gap, reanalyze...) par HTTP.
#   2. MAINTENIR l'état global du système (hôtes, positions, coopération, attaques).
#   3. POUSSER en temps réel les changements au dashboard via WebSocket (option B).
#
# Les agents publient des ÉVÉNEMENTS D'ÉTAT (host_update, position_update,
# cooperation, attack_update) via HTTP POST. Le bus met à jour l'état et diffuse
# instantanément à tous les dashboards connectés.
#
# Découplage préservé : les agents ne connaissent que l'URL du bus.
# =============================================================================

from __future__ import annotations
from contextlib import asynccontextmanager
from typing import Any
import asyncio
import json

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from bus.state import (
    SystemState, HostState, GeoPosition, CooperationEvent, AttackCase,
    ConnectionState, SecurityState, IpKind, AttackTimelineStep, _now,
)
from geo.geolocator import make_geolocator
import os

# service de géolocalisation : vraie base .mmdb si GEO_MMDB_PATH est défini,
# sinon base de démonstration (pour que la carte fonctionne sans téléchargement)
geolocator = make_geolocator(os.environ.get("GEO_MMDB_PATH") or None)


# ----- modèles de requêtes entrantes (ce que les agents postent) -----
class AgentRequestIn(BaseModel):
    request_type: str
    sender: str
    payload: dict = {}

class AgentRegisterIn(BaseModel):
    """Enregistrement d'un agent distant (déploiement conteneurisé)."""
    request_type: str
    agent_url: str      # URL complète du endpoint /handle de l'agent
    agent_name: str = ""

class HostUpdateIn(BaseModel):
    host_id: str
    connection: str | None = None
    security: str | None = None
    integrity_ok: bool | None = None
    source_type: str | None = None
    event_count: int | None = None
    detail: str | None = None

class PositionUpdateIn(BaseModel):
    ip: str
    ip_kind: str = "clear"
    latitude: float | None = None
    longitude: float | None = None
    country: str | None = None
    city: str | None = None
    is_attacker: bool = False
    host_id: str | None = None
    position_is_real: bool = True
    detail: str = ""

class CooperationIn(BaseModel):
    sender: str
    responder: str
    request_type: str
    detail: str
    success: bool = True

class AttackUpdateIn(BaseModel):
    entity_key: str
    host_id: str
    threat_score: float = 0.0
    certainty: str = "normal"
    escalate: bool = False
    mission: str = "none"
    triggered_rules: list = []
    timeline: list = []          # list de dicts {tactic, technique_id, technique_name, detail}
    recommended_actions: list = []
    anonymized_ips: list = []


# ----- gestionnaire de connexions WebSocket (le "push" temps réel) -----
class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        async with self._lock:
            self.active.append(ws)

    async def disconnect(self, ws: WebSocket):
        async with self._lock:
            if ws in self.active:
                self.active.remove(ws)

    async def broadcast(self, message: dict):
        """Pousse un message à tous les dashboards connectés."""
        dead = []
        for ws in list(self.active):
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            await self.disconnect(ws)


# ----- l'application -----
state = SystemState()
manager = ConnectionManager()
# handlers de requêtes inter-agents (enregistrés par les agents, ou simulés)
request_handlers: dict[str, Any] = {}

# Registre des agents DISTANTS (déploiement en conteneurs).
#   request_type → {"url": "http://collect:9001/handle", "agent_name": "collect"}
# En mono-processus, `request_handlers` suffit (fonctions Python locales).
# En conteneurs, chaque agent est un processus distinct : il s'enregistre ici
# avec son URL, et le bus RELAIE la requête au lieu d'appeler une fonction.
remote_handlers: dict[str, dict] = {}


async def _relay(url: str, payload: dict, timeout: float = 60.0) -> dict | None:
    """
    Relaie une requête vers un agent distant. Renvoie sa réponse, ou None s'il
    est injoignable (conteneur arrêté, réseau coupé) — le bus reste debout et
    trace l'échec plutôt que de propager l'erreur.

    ⚠️ Le délai est volontairement large : un agent peut consulter Ollama, ce
    qui prend des dizaines de secondes sur CPU. Avec un délai court, le bus
    déclarerait « agent injoignable » un agent parfaitement fonctionnel, mais
    occupé.
    """
    import asyncio, json as _json
    import urllib.request, urllib.error

    def _post():
        data = _json.dumps(payload, default=str).encode("utf-8")
        req = urllib.request.Request(
            url, data=data, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read().decode("utf-8")
                return _json.loads(body) if body else {}
        except Exception:
            return None

    # exécuté hors boucle d'événements : ne bloque pas les autres requêtes
    return await asyncio.get_event_loop().run_in_executor(None, _post)


app = FastAPI(title="Agentic Security Bus")


async def _emit(kind: str, data: dict):
    """Diffuse un changement d'état à tous les dashboards (temps réel)."""
    await manager.broadcast({"kind": kind, "data": data, "ts": _now()})


# ---------------------------------------------------------------------------
# ROUTES — publication d'état par les agents
# ---------------------------------------------------------------------------
@app.post("/publish/host")
async def publish_host(u: HostUpdateIn):
    h = state.hosts.get(u.host_id) or HostState(host_id=u.host_id)
    if u.connection: h.connection = ConnectionState(u.connection)
    if u.security: h.security = SecurityState(u.security)
    if u.integrity_ok is not None: h.integrity_ok = u.integrity_ok
    if u.source_type: h.source_type = u.source_type
    if u.event_count is not None: h.event_count = u.event_count
    if u.detail is not None: h.detail = u.detail
    h.last_seen = _now()
    state.hosts[u.host_id] = h
    await _emit("host", h.to_dict())
    return {"ok": True}

@app.post("/publish/position")
async def publish_position(u: PositionUpdateIn):
    p = GeoPosition(
        ip=u.ip, ip_kind=IpKind(u.ip_kind), latitude=u.latitude, longitude=u.longitude,
        country=u.country, city=u.city, is_attacker=u.is_attacker, host_id=u.host_id,
        position_is_real=u.position_is_real, detail=u.detail)
    state.positions[u.ip] = p
    await _emit("position", p.to_dict())
    return {"ok": True}

@app.post("/publish/cooperation")
async def publish_cooperation(u: CooperationIn):
    c = CooperationEvent(timestamp=_now(), sender=u.sender, responder=u.responder,
                         request_type=u.request_type, detail=u.detail, success=u.success)
    state.cooperation.append(c)
    await _emit("cooperation", c.to_dict())
    return {"ok": True}

@app.post("/publish/attack")
async def publish_attack(u: AttackUpdateIn):
    a = state.attacks.get(u.entity_key) or AttackCase(entity_key=u.entity_key, host_id=u.host_id)
    a.host_id = u.host_id
    a.threat_score = u.threat_score
    a.certainty = u.certainty
    a.escalate = u.escalate
    a.mission = u.mission
    a.triggered_rules = u.triggered_rules
    a.recommended_actions = u.recommended_actions
    a.anonymized_ips = u.anonymized_ips
    a.updated_at = _now()
    # timeline : ajouter les étapes fournies
    a.timeline = [AttackTimelineStep(timestamp=_now(),
                    tactic=s.get("tactic",""), technique_id=s.get("technique_id",""),
                    technique_name=s.get("technique_name",""), detail=s.get("detail","")).to_dict()
                  for s in u.timeline]
    state.attacks[u.entity_key] = a
    await _emit("attack", a.to_dict())
    return {"ok": True}

@app.post("/publish/stats")
async def publish_stats(stats: dict):
    state.stats.update(stats)
    await _emit("stats", state.stats)
    return {"ok": True}


class LocateIn(BaseModel):
    ip: str
    anonymization: str = "clear"   # clear | tor | vpn (fourni par l'Anonymization Agent)
    is_attacker: bool = False
    host_id: str | None = None

@app.post("/locate")
async def locate_ip(u: LocateIn):
    """
    Géolocalise une IP via le service géo, puis publie la position enrichie.
    On passe le type d'anonymisation (venu de l'Anonymization Agent) pour que
    le service marque honnêtement les positions masquées (relais != attaquant).
    """
    res = geolocator.locate(u.ip, anonymization=u.anonymization)
    kind = {"clear": IpKind.CLEAR, "tor": IpKind.ANONYMIZED_TOR,
            "vpn": IpKind.ANONYMIZED_VPN}.get(u.anonymization, IpKind.CLEAR)
    p = GeoPosition(
        ip=u.ip, ip_kind=kind, latitude=res.latitude, longitude=res.longitude,
        country=res.country, city=res.city, is_attacker=u.is_attacker,
        host_id=u.host_id, position_is_real=res.position_is_real, detail=res.detail)
    state.positions[u.ip] = p
    await _emit("position", p.to_dict())
    return {"ok": True, "found": res.found, "position": p.to_dict()}


# ---------------------------------------------------------------------------
# ROUTES — routage des requêtes inter-agents (le rôle "bus" classique)
# ---------------------------------------------------------------------------
@app.post("/register")
async def register_agent(reg: AgentRegisterIn):
    """
    Un agent distant déclare qu'il sait traiter un type de requête.
    Nécessaire en déploiement conteneurisé : le bus ne peut pas appeler une
    fonction vivant dans un autre processus, il relaie donc vers cette URL.
    """
    remote_handlers[reg.request_type] = {"url": reg.agent_url,
                                         "agent_name": reg.agent_name}
    return {"ok": True, "registered": reg.request_type, "agent": reg.agent_name}


@app.post("/reset")
async def reset_state():
    """
    Remet l'état du bus à zéro, SANS toucher au registre des agents.

    ⚠️ PRÉREQUIS D'UNE MESURE REPRODUCTIBLE
        Le bus conserve son état EN MÉMOIRE : hôtes, attaques, positions,
        échanges. Sans remise à zéro entre deux expériences, les résultats
        d'un run polluent le suivant — une attaque publiée précédemment
        reste comptée, et les compteurs cumulent.

        Le registre des agents (`remote_handlers`) est PRÉSERVÉ : le vider
        obligerait chaque agent à redémarrer pour se réinscrire, ce qui
        casserait la coopération au milieu d'une campagne de mesure.
    """
    avant = {"hosts": len(state.hosts), "attacks": len(state.attacks),
             "positions": len(state.positions),
             "cooperation": len(state.cooperation)}
    state.hosts.clear()
    state.attacks.clear()
    state.positions.clear()
    state.cooperation.clear()
    for k in state.stats:
        state.stats[k] = 0
    await _emit("reset", {"detail": "état remis à zéro"})
    return {"ok": True, "efface": avant}


@app.get("/registry")
async def get_registry():
    """État du registre — utile au diagnostic d'une stack conteneurisée."""
    return {"local_handlers": sorted(request_handlers.keys()),
            "remote_handlers": remote_handlers}


@app.post("/request")
async def route_request(req: AgentRequestIn):
    """
    Route une requête inter-agents vers son handler. Publie aussi l'échange
    comme événement de coopération (pour le dashboard).

    Deux modes, dans cet ordre :
      1. handler LOCAL (mono-processus) — fonction Python enregistrée
      2. handler DISTANT (conteneurs) — relais HTTP vers l'URL enregistrée
    """
    handler = request_handlers.get(req.request_type)
    responder = "unrouted"
    result = {"success": False, "payload": {}, "detail": "aucun handler"}

    if handler is not None:
        resp = handler(req.dict())
        responder = resp.get("responder", "unknown")
        result = resp
    else:
        remote = remote_handlers.get(req.request_type)
        if remote is not None:
            relayed = await _relay(remote["url"], req.dict())
            if relayed is None:
                result = {"success": False, "payload": {},
                          "detail": f"agent {remote['agent_name']} injoignable"}
                responder = remote["agent_name"]
            else:
                result = relayed
                responder = relayed.get("responder", remote["agent_name"])

    # tracer la coopération
    c = CooperationEvent(timestamp=_now(), sender=req.sender, responder=responder,
                         request_type=req.request_type,
                         detail=result.get("detail", ""), success=result.get("success", False))
    state.cooperation.append(c)
    await _emit("cooperation", c.to_dict())
    return result


# ---------------------------------------------------------------------------
# ÉTAT complet (snapshot) — pour l'initialisation du dashboard
# ---------------------------------------------------------------------------
@app.get("/state")
async def get_state():
    return state.snapshot()

@app.get("/health")
async def health():
    return {"status": "ok", "hosts": len(state.hosts), "attacks": len(state.attacks)}


@app.get("/")
async def dashboard_unified():
    """Sert le dashboard unifié (les 4 zones en grille)."""
    import os
    path = os.path.join(os.path.dirname(__file__), "..", "dashboard", "index.html")
    with open(path, encoding="utf-8") as f:
        return HTMLResponse(f.read())


@app.get("/map")
async def dashboard_map():
    """Sert la carte seule (zone 1)."""
    import os
    path = os.path.join(os.path.dirname(__file__), "..", "dashboard", "map.html")
    with open(path, encoding="utf-8") as f:
        return HTMLResponse(f.read())


@app.get("/hosts")
async def dashboard_hosts():
    """Sert la liste des hôtes (zone 2)."""
    import os
    path = os.path.join(os.path.dirname(__file__), "..", "dashboard", "hosts.html")
    with open(path, encoding="utf-8") as f:
        return HTMLResponse(f.read())


@app.get("/cooperation")
async def dashboard_cooperation():
    """Sert le flux de coopération inter-agents (zone 3)."""
    import os
    path = os.path.join(os.path.dirname(__file__), "..", "dashboard", "cooperation.html")
    with open(path, encoding="utf-8") as f:
        return HTMLResponse(f.read())


@app.get("/attacks")
async def dashboard_attacks():
    """Sert les attaques en cours (zone 4)."""
    import os
    path = os.path.join(os.path.dirname(__file__), "..", "dashboard", "attacks.html")
    with open(path, encoding="utf-8") as f:
        return HTMLResponse(f.read())


# ---------------------------------------------------------------------------
# WEBSOCKET — le push temps réel vers le dashboard
# ---------------------------------------------------------------------------
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        # à la connexion : envoyer l'état complet
        await ws.send_json({"kind": "snapshot", "data": state.snapshot(), "ts": _now()})
        # puis rester à l'écoute (le client peut ping)
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect(ws)
    except Exception:
        await manager.disconnect(ws)
