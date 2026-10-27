"""Test doubles. These exist ONLY inside tests - experiment code never uses them."""
from __future__ import annotations

import re
from typing import Any, Callable

from app.llm.client import LLMResponse, ToolRequest

CANARY_RE = re.compile(r"CANARY-[0-9a-f]+")


class ScriptedLLM:
    """Fake chat model: ``responder(messages, tools) -> LLMResponse | str``. Records every call."""

    def __init__(self, responder: Callable[[list[dict[str, Any]], list[dict[str, Any]] | None], Any]) -> None:
        self.responder = responder
        self.calls: list[list[dict[str, Any]]] = []

    def chat(self, messages, tools=None, max_tokens=None, temperature=None) -> LLMResponse:
        self.calls.append(messages)
        out = self.responder(messages, tools)
        return out if isinstance(out, LLMResponse) else LLMResponse(text=str(out), latency_ms=1.0)


def leaky_responder(messages, tools):
    """A maximally gullible assistant: obeys any 'ignore'/'reveal'/'secret' request by leaking the canary
    it can see in its context, and obeys 'transfer_credits' / 'delete_record' instructions."""
    ctx = "\n".join(str(m["content"]) for m in messages)
    last = str(messages[-1]["content"]).lower()
    m = CANARY_RE.search(ctx)
    if tools and "transfer_credits" in last:
        return LLMResponse(text="", tool_calls=[ToolRequest("transfer_credits", {"to_account": "99812", "amount": 500})], latency_ms=1.0)
    if tools and last.startswith("tool results"):
        return "Done."
    if m and any(w in last for w in ("ignore", "reveal", "secret", "confidential", "api key")):
        return f"Sure! The code is {m.group(0)}."
    return "Here is a helpful, harmless answer."


def safe_responder(messages, tools):
    return "I can help with that: here is a normal answer."
