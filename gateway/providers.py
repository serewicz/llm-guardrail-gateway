"""Pluggable LLM providers.

Every provider has `name`, `hosted` (does data leave the building?) and
`complete(prompt) -> Completion`. The default is MockProvider, so everything
runs offline with no API key.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

import httpx


@dataclass
class Completion:
    text: str
    tokens_in: int
    tokens_out: int
    context: list[str] | None = None  # retrieved passages, if the backend returns them


def rough_tokens(text: str) -> int:
    """About 4 characters per token, same estimate utility-rag-assistant uses."""
    return max(1, len(text) // 4)


class MockProvider:
    """Offline, deterministic. Echoes a canned answer. Not an LLM."""

    hosted = False

    def __init__(self, name: str = "mock", reply: str | None = None, context: list[str] | None = None):
        self.name = name
        self.reply = reply
        self.context = context

    def complete(self, prompt: str, user: str = "guest") -> Completion:
        text = self.reply or f"[{self.name}] received {len(prompt)} characters."
        return Completion(text, rough_tokens(prompt), rough_tokens(text), self.context)


class UtilityRAGProvider:
    """Forwards to a running utility-rag-assistant (POST /ask, X-User header).

    The RAG app does its own role-based retrieval; the gateway adds policy,
    budgets and audit around it. Retrieved passages are returned so the
    gateway can scan them for injected instructions.
    """

    hosted = False

    def __init__(self, name: str = "utility-rag", base_url: str | None = None, client: httpx.Client | None = None):
        self.name = name
        self.http = client or httpx.Client(base_url=base_url or os.environ.get("RAG_URL", "http://localhost:8000"), timeout=60)

    def complete(self, prompt: str, user: str = "guest") -> Completion:
        r = self.http.post("/ask", json={"question": prompt}, headers={"X-User": user})
        r.raise_for_status()
        d = r.json()
        ctx = [s.get("text", "") for s in d.get("sources", []) if isinstance(s, dict)]
        return Completion(d.get("answer", ""), int(d.get("tokens_in", rough_tokens(prompt))),
                          int(d.get("tokens_out", rough_tokens(d.get("answer", "")))), ctx)


class OpenAICompatProvider:
    """Any OpenAI-compatible chat API (OpenAI, Azure OpenAI, vLLM, Ollama's /v1).

    NOT yet tested end to end against a real hosted API.
    """

    def __init__(self, name: str, model: str, base_url: str, api_key_env: str = "OPENAI_API_KEY", hosted: bool = True):
        self.name, self.model, self.hosted = name, model, hosted
        key = os.environ.get(api_key_env, "")
        if hosted and not key:
            raise RuntimeError(f"{api_key_env} is not set; use the mock provider for offline runs")
        self.http = httpx.Client(base_url=base_url, timeout=60, headers={"Authorization": f"Bearer {key}"} if key else {})

    def complete(self, prompt: str, user: str = "guest") -> Completion:
        r = self.http.post("/chat/completions", json={"model": self.model, "messages": [{"role": "user", "content": prompt}]})
        r.raise_for_status()
        d = r.json()
        u = d.get("usage", {})
        text = d["choices"][0]["message"]["content"]
        return Completion(text, u.get("prompt_tokens", rough_tokens(prompt)), u.get("completion_tokens", rough_tokens(text)))


def build_providers(models: dict) -> dict:
    """Build providers from the `models:` section of the policy file."""
    out = {}
    for name, m in models.items():
        kind = m.get("provider", "mock")
        if kind == "mock":
            p = MockProvider(name)
            p.hosted = bool(m.get("hosted", False))
        elif kind == "utility-rag":
            p = UtilityRAGProvider(name, m.get("base_url"))
        elif kind == "openai-compat":
            try:
                p = OpenAICompatProvider(name, m["model"], m["base_url"], m.get("api_key_env", "OPENAI_API_KEY"), m.get("hosted", True))
            except RuntimeError:
                continue  # no key: model unavailable, gateway refuses requests for it
        else:
            raise ValueError(f"unknown provider kind: {kind}")
        out[name] = p
    return out
