from __future__ import annotations
from dataclasses import dataclass, field
from typing import Protocol, Optional
import json
import re

from .mitre_rag import MitreRAG, RetrievedTechnique, sequence_to_query


class LLMClient(Protocol):
    def generate(self, prompt: str) -> str: ...


@dataclass
class AttributedTechnique:
    technique_id: str
    name: str
    tactic: str
    confidence: str


@dataclass
class AttackInterpretation:
    sequence_id: str
    hypothesis: str
    techniques: list[AttributedTechnique] = field(default_factory=list)
    raw_response: str = ""


def build_prompt(seq, candidates: list[RetrievedTechnique]) -> str:
    lines = []
    for e in seq.events:
        parts = [e.event_time.strftime("%H:%M:%S"), e.category.value]
        if e.process_name:
            parts.append(f"process={e.process_name}")
        if e.command_line:
            parts.append(f"cmd={e.command_line[:120]}")
        if e.destination_ip:
            parts.append(f"dst={e.destination_ip}:{e.destination_port}")
        lines.append("  - " + " | ".join(parts))
    seq_desc = "\n".join(lines)

    cand_lines = []
    for rt in candidates:
        t = rt.technique
        cand_lines.append(f"  - {t.technique_id} | {t.name} | {t.tactic} | {t.description}")
    cand_desc = "\n".join(cand_lines)

    return f"""You are a cybersecurity analyst. Analyze the following sequence of system events from a Windows host and determine the likely attack.

EVENT SEQUENCE (host={seq.host}):
{seq_desc}

CANDIDATE MITRE ATT&CK TECHNIQUES (you MUST only choose from this list, using exact IDs):
{cand_desc}

INSTRUCTIONS:
1. Write a brief hypothesis (2-3 sentences) describing the likely attack narrative.
2. Select the MITRE techniques that apply, ONLY from the candidate list above.
3. For each, give a confidence: high, medium, or low.

Respond ONLY in JSON with this exact structure:
{{
  "hypothesis": "...",
  "techniques": [
    {{"technique_id": "T....", "confidence": "high|medium|low"}}
  ]
}}"""


def parse_response(raw: str, candidates: list[RetrievedTechnique],
                   sequence_id: str) -> AttackInterpretation:
    valid = {rt.technique.technique_id: rt.technique for rt in candidates}
    hypothesis = ""
    techniques: list[AttributedTechnique] = []
    data = _extract_json(raw)
    if data:
        hypothesis = str(data.get("hypothesis", "")).strip()
        for item in data.get("techniques", []):
            tid = str(item.get("technique_id", "")).strip()
            conf = str(item.get("confidence", "medium")).strip().lower()
            if tid in valid:   # ANTI-HALLUCINATION
                t = valid[tid]
                techniques.append(AttributedTechnique(
                    technique_id=tid, name=t.name, tactic=t.tactic,
                    confidence=conf if conf in ("high", "medium", "low") else "medium",
                ))
    return AttackInterpretation(
        sequence_id=sequence_id, hypothesis=hypothesis,
        techniques=techniques, raw_response=raw,
    )


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


class InterpretationEngine:
    def __init__(self, llm: LLMClient, rag: MitreRAG, k_candidates: int = 8):
        self.llm = llm
        self.rag = rag
        self.k = k_candidates

    def interpret(self, seq) -> AttackInterpretation:
        query = sequence_to_query(seq)
        candidates = self.rag.retrieve(query, k=self.k)
        prompt = build_prompt(seq, candidates)
        raw = self.llm.generate(prompt)
        return parse_response(raw, candidates, seq.sequence_id)
