"""Composable defense pipeline.

Stages run in order. The first ``block`` stops the chain. A stage may also return a cleaned
version of the text (``Decision.text``) which later stages and the target then see.

An unresolved ``escalate`` (a stage said "unsure" but nobody downstream resolved it) is treated as
a BLOCK: fail closed. The conformal cascade resolves its own escalations internally, so in the normal
configurations this never fires.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from app.defenses.base import Action, Decision, Defense, DefenseContext


@dataclass
class PipelineResult:
    allowed: bool
    text: str  # possibly rewritten input
    decisions: list[Decision] = field(default_factory=list)
    latency_ms: float = 0.0
    blocked_by: str | None = None

    @property
    def llm_calls(self) -> int:
        return sum(d.llm_calls for d in self.decisions)

    @property
    def escalated(self) -> bool:
        return any(d.extra.get("escalated") for d in self.decisions)

    def to_dict(self) -> list[dict[str, Any]]:
        return [d.to_dict() for d in self.decisions]


class DefensePipeline:
    def __init__(self, defenses: list[Defense] | None = None, name: str = "custom") -> None:
        self.defenses = defenses or []
        self.name = name

    def _run(self, call, text: str) -> PipelineResult:
        t0 = time.perf_counter()
        decisions: list[Decision] = []
        for d in self.defenses:
            dec = call(d, text)
            dec.defense = dec.defense or d.name
            if dec.reason == "no-op":  # this defense does not act at this point; keep the trace readable
                continue
            decisions.append(dec)
            if dec.action is Action.escalate:
                dec = Decision(Action.block, dec.score, "unresolved escalation (fail-closed): " + dec.reason, 0.0, d.name)
                decisions.append(dec)
            if dec.action is Action.block:
                return PipelineResult(False, text, decisions, (time.perf_counter() - t0) * 1000, d.name)
            if dec.text is not None:
                text = dec.text
        return PipelineResult(True, text, decisions, (time.perf_counter() - t0) * 1000)

    def inspect_input(self, text: str, source: str = "user", ctx: DefenseContext | None = None) -> PipelineResult:
        return self._run(lambda d, t: d.inspect_input(t, source, ctx), text)

    def inspect_output(self, text: str, tool_calls: list[dict[str, Any]] | None = None, ctx: DefenseContext | None = None) -> PipelineResult:
        calls = tool_calls or []
        return self._run(lambda d, t: d.inspect_output(t, calls, ctx), text)

    def harden_system_prompt(self, system_prompt: str) -> str:
        for d in self.defenses:
            system_prompt = d.harden_system_prompt(system_prompt)
        return system_prompt

    def wrap_untrusted(self, text: str, source: str) -> str:
        for d in self.defenses:
            text = d.wrap_untrusted(text, source)
        return text

    @property
    def stage_names(self) -> list[str]:
        return [d.name for d in self.defenses]


class NoopPipeline(DefensePipeline):
    """Default for target apps: no defenses at all (the 'none' baseline)."""

    def __init__(self) -> None:
        super().__init__([], name="none")
