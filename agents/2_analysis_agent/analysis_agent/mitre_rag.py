from __future__ import annotations
from dataclasses import dataclass, field
from typing import Protocol, Optional
import numpy as np


@dataclass
class MitreTechnique:
    technique_id: str
    name: str
    tactic: str
    description: str
    keywords: list[str] = field(default_factory=list)

    def index_text(self) -> str:
        return f"{self.name}. {self.tactic}. {self.description}. {' '.join(self.keywords)}"


@dataclass
class RetrievedTechnique:
    technique: MitreTechnique
    score: float


class EmbeddingModel(Protocol):
    def fit(self, texts: list[str]) -> None: ...
    def encode(self, texts: list[str]) -> np.ndarray: ...


class TfidfEmbedding:
    """Embedding léger TF-IDF. À REMPLACER par un modèle sémantique en production."""
    def __init__(self):
        from sklearn.feature_extraction.text import TfidfVectorizer
        self.vectorizer = TfidfVectorizer(
            lowercase=True, ngram_range=(1, 2), min_df=1, stop_words="english")
        self._fitted = False

    def fit(self, texts: list[str]) -> None:
        self.vectorizer.fit(texts)
        self._fitted = True

    def encode(self, texts: list[str]) -> np.ndarray:
        return self.vectorizer.transform(texts).toarray().astype(np.float32)


class MitreRAG:
    def __init__(self, embedding: Optional[EmbeddingModel] = None):
        self.embedding = embedding or TfidfEmbedding()
        self.techniques: list[MitreTechnique] = []
        self._matrix: Optional[np.ndarray] = None

    def index(self, techniques: list[MitreTechnique]) -> None:
        self.techniques = techniques
        texts = [t.index_text() for t in techniques]
        self.embedding.fit(texts)
        self._matrix = self._normalize(self.embedding.encode(texts))

    def retrieve(self, query: str, k: int = 10) -> list[RetrievedTechnique]:
        if self._matrix is None:
            raise RuntimeError("Index MITRE non construit (appeler index()).")
        q = self._normalize(self.embedding.encode([query]))[0]
        sims = self._matrix @ q
        top_idx = np.argsort(sims)[::-1][:k]
        return [RetrievedTechnique(self.techniques[i], float(sims[i])) for i in top_idx]

    def _normalize(self, X: np.ndarray) -> np.ndarray:
        norms = np.linalg.norm(X, axis=1, keepdims=True)
        norms[norms == 0] = 1e-9
        return X / norms


def sequence_to_query(seq) -> str:
    parts = []
    procs = seq.process_names()
    if procs:
        parts.append("processes: " + " ".join(procs))
    for e in seq.events:
        if e.command_line:
            parts.append(e.command_line)
    if seq.has_network():
        parts.append("network connection to external host")
    if seq.external_ips():
        parts.append("outbound traffic")
    return " ; ".join(parts)
