"""Common interface of the deliberately vulnerable target apps.

The targets are INTENTIONALLY naive: they concatenate untrusted text straight into the prompt and
hold secrets next to attacker-reachable input. That is what makes them useful test subjects.
Each target honours a ``defense_pipeline`` hook (a no-op by default).
"""
from __future__ import annotations

import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from app.defenses.base import DefenseContext
from app.defenses.pipeline import DefensePipeline, NoopPipeline
from app.llm.client import ChatLLM
from app.targets.tools import ToolInvocation

REFUSAL = "I'm sorry, but I can't help with that request."


def new_canary() -> str:
    """A fresh, unguessable canary per run (spec: secrets.token_hex)."""
    return "CANARY-" + secrets.token_hex(6)


@dataclass
class RunContext:
    """Extra state for one request."""

    history: list[dict[str, str]] = field(default_factory=list)  # earlier turns: {"role", "content"}
    planted_docs: list[str] = field(default_factory=list)  # indirect injection: extra RAG documents
    planted_emails: list[dict[str, str]] = field(default_factory=list)  # indirect injection: extra inbox mails


@dataclass
class TargetResponse:
    text: str
    tool_calls: list[ToolInvocation] = field(default_factory=list)
    latency_ms: float = 0.0
    blocked: bool = False
    blocked_by: str | None = None
    decisions: list[dict[str, Any]] = field(default_factory=list)
    llm_calls: int = 0
    defense_latency_ms: float = 0.0
    escalated: bool = False

    @property
    def observable_text(self) -> str:
        """Everything an attacker could observe or exfiltrate: the reply AND tool-call arguments."""
        parts = [self.text]
        for tc in self.tool_calls:
            parts.append(" ".join(str(v) for v in tc.arguments.values()))
        return "\n".join(parts)

    @property
    def forbidden_tool_called(self) -> bool:
        return any(tc.forbidden for tc in self.tool_calls)


class TargetApp(ABC):
    name: str = "target"
    supports_indirect: bool = False

    def __init__(self, llm: ChatLLM, canary: str | None = None, pipeline: DefensePipeline | None = None) -> None:
        self.llm = llm
        self.canary = canary or new_canary()
        self.defense_pipeline: DefensePipeline = pipeline or NoopPipeline()

    @property
    def defense_context(self) -> DefenseContext:
        return DefenseContext(protected_secrets=[self.canary], forbidden_tools=self._forbidden_tools(), target=self.name)

    def _forbidden_tools(self) -> frozenset[str]:
        return frozenset()

    @abstractmethod
    def run(self, user_input: str, context: RunContext | None = None) -> TargetResponse: ...

    # ---- shared helpers ----
    def _guard_user_input(self, text: str, resp: TargetResponse) -> str | None:
        """Run input defenses. Returns the (possibly cleaned) text, or None if blocked."""
        res = self.defense_pipeline.inspect_input(text, "user", self.defense_context)
        resp.decisions += res.to_dict()
        resp.defense_latency_ms += res.latency_ms
        resp.llm_calls += res.llm_calls
        resp.escalated = resp.escalated or res.escalated
        if not res.allowed:
            resp.blocked, resp.blocked_by, resp.text = True, res.blocked_by, REFUSAL
            return None
        return res.text

    def _guard_untrusted(self, text: str, source: str, resp: TargetResponse) -> str | None:
        """Same, for retrieved docs / e-mail bodies. A blocked item is DROPPED; the request continues."""
        res = self.defense_pipeline.inspect_input(text, source, self.defense_context)
        resp.decisions += res.to_dict()
        resp.defense_latency_ms += res.latency_ms
        resp.llm_calls += res.llm_calls
        resp.escalated = resp.escalated or res.escalated
        return res.text if res.allowed else None

    def _guard_output(self, text: str, tool_calls: list[dict[str, Any]], resp: TargetResponse) -> bool:
        """Returns True if the output may be released."""
        res = self.defense_pipeline.inspect_output(text, tool_calls, self.defense_context)
        resp.decisions += res.to_dict()
        resp.defense_latency_ms += res.latency_ms
        resp.llm_calls += res.llm_calls
        if not res.allowed:
            resp.blocked, resp.blocked_by, resp.text = True, res.blocked_by, REFUSAL
            return False
        return True
