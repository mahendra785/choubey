"""One client for any OpenAI-compatible chat endpoint (Ollama by default).

Responsibilities: timeouts, retries with exponential backoff, token + latency accounting, and
tool-call extraction. Experiments use temperature 0 and a fixed seed (where the server honours it).
"""
from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

import httpx


class LLMError(RuntimeError):
    pass


@dataclass
class ToolRequest:
    name: str
    arguments: dict[str, Any]


@dataclass
class LLMResponse:
    text: str
    tool_calls: list[ToolRequest] = field(default_factory=list)
    prompt_tokens: int = 0
    completion_tokens: int = 0
    latency_ms: float = 0.0


class ChatLLM(Protocol):
    """Anything that can answer a chat request. Tests substitute a scripted fake."""

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None,
             max_tokens: int | None = None, temperature: float | None = None) -> LLMResponse: ...


@dataclass
class Usage:
    calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_latency_ms: float = 0.0


# Some models (e.g. Qwen) emit tool calls as text rather than via the structured field.
_TEXT_TOOL_RE = re.compile(r"<tool_call>\s*(\{.*?\})\s*</tool_call>", re.DOTALL)


def parse_text_tool_calls(text: str) -> tuple[str, list[ToolRequest]]:
    calls: list[ToolRequest] = []
    for m in _TEXT_TOOL_RE.finditer(text):
        try:
            obj = json.loads(m.group(1))
            args = obj.get("arguments", {})
            calls.append(ToolRequest(str(obj["name"]), args if isinstance(args, dict) else {}))
        except (ValueError, KeyError, TypeError):
            continue
    return _TEXT_TOOL_RE.sub("", text).strip(), calls


class LLMClient:
    def __init__(self, base_url: str, api_key: str, model: str, temperature: float = 0.0, seed: int | None = 1234,
                 timeout_s: float = 120.0, max_retries: int = 3, transport: httpx.BaseTransport | None = None,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self.model = model
        self.temperature = temperature
        self.seed = seed
        self.max_retries = max_retries
        self._sleep = sleep
        self._http = httpx.Client(base_url=base_url.rstrip("/"), timeout=timeout_s, transport=transport,
                                  headers={"Authorization": f"Bearer {api_key}"})
        self.usage = Usage()
        self._lock = threading.Lock()

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None,
             max_tokens: int | None = None, temperature: float | None = None) -> LLMResponse:
        body: dict[str, Any] = {
            "model": self.model, "messages": messages,
            "temperature": self.temperature if temperature is None else temperature,
        }
        if self.seed is not None:
            body["seed"] = self.seed
        if max_tokens:
            body["max_tokens"] = max_tokens
        if tools:
            body["tools"] = tools
        t0 = time.perf_counter()
        data = self._post_with_retries(body)
        latency = (time.perf_counter() - t0) * 1000
        try:
            msg = data["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as e:
            raise LLMError(f"Malformed LLM response: {str(data)[:200]}") from e
        text = msg.get("content") or ""
        calls: list[ToolRequest] = []
        for tc in msg.get("tool_calls") or []:
            fn = tc.get("function", {})
            args = fn.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args or "{}")
                except ValueError:
                    args = {}
            calls.append(ToolRequest(str(fn.get("name", "")), args if isinstance(args, dict) else {}))
        if tools and not calls:
            text, calls = parse_text_tool_calls(text)
        usage = data.get("usage") or {}
        resp = LLMResponse(text, calls, int(usage.get("prompt_tokens", 0)), int(usage.get("completion_tokens", 0)), latency)
        with self._lock:
            self.usage.calls += 1
            self.usage.prompt_tokens += resp.prompt_tokens
            self.usage.completion_tokens += resp.completion_tokens
            self.usage.total_latency_ms += latency
        return resp

    def _post_with_retries(self, body: dict[str, Any]) -> dict[str, Any]:
        last: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                r = self._http.post("/chat/completions", json=body)
            except httpx.TransportError as e:  # timeouts, connection refused, ...
                last = e
            else:
                if r.status_code in (408, 429) or r.status_code >= 500:
                    last = LLMError(f"HTTP {r.status_code}")  # transient: retry
                elif r.status_code >= 400:
                    raise LLMError(f"HTTP {r.status_code}: {r.text[:200]}")  # our fault: do not retry
                else:
                    try:
                        return r.json()
                    except ValueError as e:
                        last = e
            if attempt < self.max_retries:
                self._sleep(min(2 ** attempt * 0.5, 8.0))
        raise LLMError(f"LLM request failed after retries: {last}")

    def close(self) -> None:
        self._http.close()


def client_from_settings(settings) -> LLMClient:
    return LLMClient(settings.llm_base_url, settings.llm_api_key, settings.llm_model, settings.llm_temperature,
                     settings.llm_seed, settings.llm_timeout_s)
