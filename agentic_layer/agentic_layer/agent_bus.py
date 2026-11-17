# =============================================================================
# BUS DE REQUÊTES INTER-AGENTS — la fondation agentique
# =============================================================================
# Transforme le pipeline unidirectionnel en système MULTI-AGENTS : les agents
# ne se contentent plus de passer leur sortie au suivant, ils peuvent se
# SOLLICITER mutuellement (perception active, coopération, action).
#
# Principe (découplage) :
#   - un agent poste une REQUÊTE TYPÉE sur le bus (il ne connaît pas qui répond)
#   - l'agent capable de ce type de requête y répond (il s'est enregistré comme
#     "handler" de ce type)
#   - tout échange est TRACÉ (auditable — on démontre la coopération)
#
# Bus EN MÉMOIRE (synchrone) : suffit à démontrer l'agentivité et reste
# testable. En production, remplaçable par une vraie file (Redis, Kafka...)
# sans changer le code des agents (même interface).
# =============================================================================

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional
import uuid


class RequestType(str, Enum):
    """Types d'interactions que le bus sait router."""
    CHECK_GAP = "check_gap"            # Analysis → Collect : "gap sur ce host à ce moment ?"
    RECOLLECT = "recollect"           # Collect → source : "redonne-moi cette plage de records"
    ATTENTION_HINT = "attention_hint" # Anonymization → Analysis : "regarde ce host de près"
    REANALYZE = "reanalyze"           # Decision → Analysis : "ré-analyse avec plus de contexte"
    EXECUTE_ACTION = "execute_action" # Decision → exécuteur : "isole la machine / bloque l'IP"


@dataclass
class AgentRequest:
    """Une requête postée sur le bus."""
    request_type: RequestType
    sender: str                              # nom de l'agent émetteur
    payload: dict = field(default_factory=dict)
    request_id: str = field(default_factory=lambda: f"req-{uuid.uuid4().hex[:8]}")
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class AgentResponse:
    """La réponse à une requête."""
    request_id: str
    responder: str
    success: bool
    payload: dict = field(default_factory=dict)
    detail: str = ""


@dataclass
class BusLogEntry:
    """Trace d'un échange (pour l'auditabilité)."""
    request: AgentRequest
    response: Optional[AgentResponse]
    handled: bool


class AgentBus:
    """
    Bus de requêtes inter-agents. Les agents s'enregistrent comme handlers de
    certains types de requêtes, puis peuvent poster des requêtes que le bus
    route vers le bon handler.
    """

    def __init__(self):
        # type de requête → fonction handler (fournie par un agent)
        self._handlers: dict[RequestType, Callable[[AgentRequest], AgentResponse]] = {}
        # journal complet des échanges (auditable)
        self.log: list[BusLogEntry] = []

    def register(self, request_type: RequestType,
                 handler: Callable[[AgentRequest], AgentResponse],
                 agent_name: str = "") -> None:
        """Un agent déclare qu'il sait traiter ce type de requête."""
        if request_type in self._handlers:
            raise ValueError(f"Un handler existe déjà pour {request_type.value} "
                             f"(enregistré, tentative par {agent_name}).")
        self._handlers[request_type] = handler

    def request(self, request: AgentRequest) -> Optional[AgentResponse]:
        """
        Poste une requête sur le bus. Le bus la route vers le handler enregistré
        pour ce type. Renvoie la réponse, ou None si personne ne gère ce type.
        """
        handler = self._handlers.get(request.request_type)
        if handler is None:
            # personne ne sait répondre : on trace quand même (utile au debug)
            self.log.append(BusLogEntry(request=request, response=None, handled=False))
            return None
        response = handler(request)
        self.log.append(BusLogEntry(request=request, response=response, handled=True))
        return response

    # --- helpers de traçabilité (pour la thèse : montrer la coopération) ---
    def interactions(self) -> list[dict]:
        """Résumé lisible de tous les échanges qui ont eu lieu."""
        out = []
        for entry in self.log:
            r = entry.request
            resp = entry.response
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
