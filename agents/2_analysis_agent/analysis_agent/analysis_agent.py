from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

from .sequence_schema import Event, Sequence
from .sequence_builder import SequenceBuilder, SequenceBuilderConfig
from .sequence_detector import SequenceDetector, SequenceVerdict
from .interpretation_engine import InterpretationEngine, AttackInterpretation


@dataclass
class ThreatVerdict:
    sequence_id: str
    host: Optional[str]
    is_attack: bool
    attack_score: float
    hypothesis: str = ""
    techniques: list = field(default_factory=list)
    sequence_summary: dict = field(default_factory=dict)
    integrity_flags: list = field(default_factory=list)
    # artefacts numériques observés dans la séquence (réseau, fichier, registre...)
    # → consommés par le Decision Agent pour le raffinement D3FEND "niveau artefacts"
    observed_artifacts: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "sequence_id": self.sequence_id,
            "host": self.host,
            "is_attack": self.is_attack,
            "attack_score": round(self.attack_score, 3),
            "hypothesis": self.hypothesis,
            "techniques": [
                {"id": t.technique_id, "name": t.name, "tactic": t.tactic,
                 "confidence": t.confidence}
                for t in self.techniques
            ],
            "sequence_summary": self.sequence_summary,
            "integrity_flags": self.integrity_flags,
            "observed_artifacts": self.observed_artifacts,
        }


@dataclass
class AnalysisOutputs:
    verdicts: list[ThreatVerdict] = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    def attacks(self) -> list[ThreatVerdict]:
        return [v for v in self.verdicts if v.is_attack]


class AnalysisAgent:
    """Détecteur de menaces (Option C : ML détecte, LLM interprète)."""

    def __init__(self, detector: SequenceDetector,
                 interpreter: Optional[InterpretationEngine] = None,
                 builder: Optional[SequenceBuilder] = None):
        self.builder = builder or SequenceBuilder()
        self.detector = detector
        self.interpreter = interpreter

    def analyze(self, events: list[Event]) -> AnalysisOutputs:
        outputs = AnalysisOutputs()
        sequences = self.builder.build(events)
        n_attacks = 0
        n_interpreted = 0
        for seq in sequences:
            det: SequenceVerdict = self.detector.predict(seq)
            verdict = ThreatVerdict(
                sequence_id=seq.sequence_id, host=seq.host,
                is_attack=det.is_attack, attack_score=det.attack_score,
                sequence_summary=seq.summary(), integrity_flags=seq.integrity_flags(),
                observed_artifacts=seq.observed_artifacts(),
            )
            if det.is_attack:
                n_attacks += 1
                if self.interpreter is not None:
                    interp: AttackInterpretation = self.interpreter.interpret(seq)
                    verdict.hypothesis = interp.hypothesis
                    verdict.techniques = interp.techniques
                    n_interpreted += 1
            outputs.verdicts.append(verdict)
        outputs.stats = {
            "n_sequences": len(sequences),
            "n_attacks": n_attacks,
            "n_normal": len(sequences) - n_attacks,
            "n_interpreted": n_interpreted,
        }
        return outputs
