#!/usr/bin/env python3
"""
Implémentation de LLMClient avec Ollama (vrai LLM local).

Branche l'Étage 2 sur un vrai modèle (Qwen3, Phi-4-mini...) servi par Ollama,
en CPU, gratuitement.

Prérequis :
  1. installer Ollama : https://ollama.com
  2. tirer un modèle : `ollama pull qwen3:4b` (ou phi4-mini, etc.)
  3. `pip install ollama`

Usage :
    from ollama_llm import OllamaLLM
    from analysis_agent import InterpretationEngine, MitreRAG
    llm = OllamaLLM(model="qwen3:4b")
    interpreter = InterpretationEngine(llm, rag)
"""
from __future__ import annotations


class OllamaLLM:
    """Client LLM via Ollama (implémente l'interface LLMClient)."""

    def __init__(self, model: str = "qwen3:4b", temperature: float = 0.2,
                 host: str = "http://localhost:11434"):
        self.model = model
        self.temperature = temperature
        self.host = host
        try:
            import ollama
            self._client = ollama.Client(host=host)
        except ImportError:
            raise ImportError("Installe le client : pip install ollama")

    def generate(self, prompt: str) -> str:
        """Appelle le modèle. Signature conforme à LLMClient."""
        response = self._client.generate(
            model=self.model,
            prompt=prompt,
            options={"temperature": self.temperature},
        )
        return response.get("response", "")


class OpenAICompatLLM:
    """
    Variante : client LLM via une API compatible OpenAI (vLLM, LM Studio,
    llama.cpp server...). Utile si tu sers ton modèle autrement qu'avec Ollama.
    """
    def __init__(self, model: str, base_url: str = "http://localhost:8000/v1",
                 api_key: str = "not-needed", temperature: float = 0.2):
        self.model = model
        self.temperature = temperature
        try:
            from openai import OpenAI
            self._client = OpenAI(base_url=base_url, api_key=api_key)
        except ImportError:
            raise ImportError("Installe le client : pip install openai")

    def generate(self, prompt: str) -> str:
        resp = self._client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=self.temperature,
        )
        return resp.choices[0].message.content or ""


if __name__ == "__main__":
    # petit test de connexion
    import sys
    model = sys.argv[1] if len(sys.argv) > 1 else "qwen3:4b"
    print(f"Test de connexion à Ollama (modèle {model})...")
    try:
        llm = OllamaLLM(model=model)
        out = llm.generate("Reply with the single word: OK")
        print(f"Réponse : {out[:100]}")
    except Exception as e:
        print(f"Erreur : {e}")
        print("Vérifie qu'Ollama tourne et que le modèle est tiré (ollama pull).")
