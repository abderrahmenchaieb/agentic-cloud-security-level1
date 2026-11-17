# =============================================================================
# GÉNÉRATEUR D'ACTIONS — le seul module IA du Decision Agent
# =============================================================================
# Pour un cas CONFIRMÉ, transforme les techniques MITRE détectées en
# RECOMMANDATIONS concrètes pour l'utilisateur.
#
# Patron identique au RAG MITRE de l'Analysis Agent :
#   base de connaissances (D3FEND + ATT&CK) → candidates réelles
#   → LLM léger FORMULE et PRIORISE (il n'invente pas les actions)
#   → parsing anti-hallucination (filtre toute action hors des candidates)
#
# Raffinement "niveau artefacts" : les candidates sont déjà filtrées par les
# artefacts réellement observés (via la base de connaissances).
#
# LLM : réutilise l'interface LLMClient (Qwen3/Phi-4 via Ollama) — le même
# que l'Analysis Agent. Testé ici avec un LLM simulé.
# =============================================================================

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Protocol, Optional
import json
import re

from .defense_knowledge import DefenseKnowledgeBase, DefensiveAction


class LLMClient(Protocol):
    def generate(self, prompt: str) -> str: ...


@dataclass
class RecommendedAction:
    action_id: str
    name: str
    source: str
    priority: str                  # "immediate" | "high" | "medium"
    reason: str = ""


@dataclass
class ActionPlan:
    entity_key: str
    host: Optional[str]
    summary: str                             # résumé lisible de la situation
    actions: list[RecommendedAction] = field(default_factory=list)
    raw_response: str = ""

    def to_dict(self) -> dict:
        return {
            "entity_key": self.entity_key,
            "host": self.host,
            "summary": self.summary,
            "actions": [
                {"id": a.action_id, "name": a.name, "source": a.source,
                 "priority": a.priority, "reason": a.reason}
                for a in self.actions
            ],
        }


def build_action_prompt(host, hypothesis, technique_ids,
                        candidates: list[DefensiveAction],
                        observed_artifacts) -> str:
    cand_lines = []
    for a in candidates:
        art = f" [opère sur {a.artifact}]" if a.artifact else ""
        cand_lines.append(f"  - {a.action_id} | {a.name} | {a.source}{art} | {a.description}")
    cand_desc = "\n".join(cand_lines)

    return f"""You are a security incident responder. An attack has been CONFIRMED on host {host}.

ATTACK HYPOTHESIS:
{hypothesis}

DETECTED MITRE TECHNIQUES: {', '.join(technique_ids)}
OBSERVED ARTIFACTS (what actually happened): {', '.join(observed_artifacts) if observed_artifacts else 'n/a'}

CANDIDATE DEFENSIVE ACTIONS (you MUST only choose from this list, using exact IDs):
{cand_desc}

INSTRUCTIONS:
1. Write a 1-2 sentence summary of the situation for the user.
2. Recommend the defensive actions to take, ONLY from the candidate list above.
3. For each, assign a priority: immediate, high, or medium.
4. Prioritize actions that address the OBSERVED artifacts.

Respond ONLY in JSON:
{{
  "summary": "...",
  "actions": [
    {{"action_id": "...", "priority": "immediate|high|medium", "reason": "..."}}
  ]
}}"""


def parse_action_response(raw: str, candidates: list[DefensiveAction],
                          entity_key: str, host) -> ActionPlan:
    """Extrait le plan d'action. FILTRE toute action hors des candidates (anti-hallucination)."""
    valid = {a.action_id: a for a in candidates}
    summary = ""
    actions: list[RecommendedAction] = []

    data = _extract_json(raw)
    if data:
        summary = str(data.get("summary", "")).strip()
        for item in data.get("actions", []):
            aid = str(item.get("action_id", "")).strip()
            prio = str(item.get("priority", "medium")).strip().lower()
            if aid in valid:                     # ANTI-HALLUCINATION
                a = valid[aid]
                actions.append(RecommendedAction(
                    action_id=aid, name=a.name, source=a.source,
                    priority=prio if prio in ("immediate", "high", "medium") else "medium",
                    reason=str(item.get("reason", "")).strip(),
                ))
    return ActionPlan(entity_key=entity_key, host=host, summary=summary,
                      actions=actions, raw_response=raw)


def _extract_json(text: str) -> Optional[dict]:
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    start = text.find("{")
    if start >= 0:
        depth = 0
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i+1])
                    except json.JSONDecodeError:
                        break
    return None


class ActionGenerator:
    """Génère un plan d'action pour un cas confirmé (LLM + base de défenses)."""

    def __init__(self, llm: LLMClient, kb: Optional[DefenseKnowledgeBase] = None):
        self.llm = llm
        self.kb = kb or DefenseKnowledgeBase()

    def generate(self, entity_key, host, hypothesis, technique_ids: list[str],
                 observed_artifacts: Optional[list[str]] = None) -> ActionPlan:
        # 1. récupérer les candidates (raffinées par artefacts observés)
        candidates = self.kb.candidate_actions(technique_ids, observed_artifacts)
        if not candidates:
            return ActionPlan(entity_key=entity_key, host=host,
                              summary="Aucune contre-mesure connue pour les techniques détectées.",
                              actions=[])
        # 2. le LLM formule et priorise
        prompt = build_action_prompt(host, hypothesis, technique_ids,
                                     candidates, observed_artifacts)
        raw = self.llm.generate(prompt)
        # 3. parser avec anti-hallucination
        return parse_action_response(raw, candidates, entity_key, host)
