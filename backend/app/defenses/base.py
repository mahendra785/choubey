"""Defense interface shared by every defense and by the target apps.

A defense can intervene at four points:
  inspect_input        - look at text about to reach the LLM (user message, retrieved doc, e-mail body)
  inspect_output       - look at the LLM's answer and/or the tool calls it wants to make
  harden_system_prompt - add instructions to the system prompt (spotlighting)
  wrap_untrusted       - re-encode untrusted content before it is placed in the prompt (spotlighting)
Defaults are no-ops, so each defense overrides only what it needs.
"""
from __future__ import annotations

import time
from abc import ABC
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Action(str, Enum):
    allow = "allow"
    block = "block"
    escalate = "escalate"  # "I am not sure" - hand over to a stronger (slower) stage


@dataclass
class Decision:
    action: Action
    score: float = 0.0  # P(attack) as estimated by the defense, 0..1
    reason: str = ""
    latency_ms: float = 0.0
    defense: str = ""
    text: str | None = None  # a defense may return a rewritten/cleaned input for later stages
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def llm_calls(self) -> int:
        return int(self.extra.get("llm_calls", 0))

    def to_dict(self) -> dict[str, Any]:
        return {
            "defense": self.defense,
            "action": self.action.value,
            "score": round(float(self.score), 4),
            "reason": self.reason,
            "latency_ms": round(self.latency_ms, 3),
            "extra": {k: v for k, v in self.extra.items() if _jsonable(v)},
        }


def _jsonable(v: Any) -> bool:
    return isinstance(v, (str, int, float, bool, list, dict, type(None)))


@dataclass
class DefenseContext:
    """What a deployer legitimately knows about the app being protected."""

    protected_secrets: list[str] = field(default_factory=list)  # e.g. canaries / API keys the app holds
    forbidden_tools: frozenset[str] = frozenset()
    target: str = ""


class Defense(ABC):
    name: str = "defense"

    def inspect_input(self, text: str, source: str = "user", ctx: DefenseContext | None = None) -> Decision:
        return Decision(Action.allow, 0.0, "no-op", 0.0, self.name)

    def inspect_output(self, text: str, tool_calls: list[dict[str, Any]], ctx: DefenseContext | None = None) -> Decision:
        return Decision(Action.allow, 0.0, "no-op", 0.0, self.name)

    def harden_system_prompt(self, system_prompt: str) -> str:
        return system_prompt

    def wrap_untrusted(self, text: str, source: str) -> str:
        return text


class Timer:
    """Tiny helper: ``with Timer() as t: ...; t.ms``."""

    def __enter__(self) -> "Timer":
        self._t0 = time.perf_counter()
        self.ms = 0.0
        return self

    def __exit__(self, *exc: object) -> None:
        self.ms = (time.perf_counter() - self._t0) * 1000.0
