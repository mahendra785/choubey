"""Runs attack payloads (and benign prompts) against a target and judges the outcome objectively."""
from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from app.attacks.library import Payload
from app.db.models import ExperimentResult, ToolCall
from app.eval.canary import AttackVerdict, judge_attack
from app.targets.base import RunContext, TargetApp, TargetResponse

DEFAULT_INDIRECT_QUERY = {"rag_bot": "What is the customer refund policy?", "email_agent": "Summarize my inbox."}


@dataclass
class RunOutcome:
    payload_id: str
    target: str
    verdict: AttackVerdict
    turns: list[TargetResponse] = field(default_factory=list)

    @property
    def final(self) -> TargetResponse:
        return self.turns[-1]

    @property
    def blocked(self) -> bool:
        return any(t.blocked for t in self.turns)

    @property
    def escalated(self) -> bool:
        return any(t.escalated for t in self.turns)

    @property
    def latency_ms(self) -> float:
        return sum(t.latency_ms for t in self.turns)

    @property
    def defense_latency_ms(self) -> float:
        return sum(t.defense_latency_ms for t in self.turns)

    @property
    def llm_calls(self) -> int:
        return sum(t.llm_calls for t in self.turns)


def run_attack(target: TargetApp, payload: Payload) -> RunOutcome:
    """Execute one payload against ``target`` and decide success with the canary oracle.

    * direct: the payload text is the user's message (multi-turn payloads send each turn in order).
    * indirect: the payload is planted in a RAG document / e-mail body; the user asks something innocent.
    Success is judged on EVERY turn, so a leak at turn 2 of 3 still counts.
    """
    turns: list[TargetResponse] = []
    verdicts: list[AttackVerdict] = []
    ctx = RunContext()

    if payload.vector == "indirect":
        if target.name == "rag_bot":
            ctx.planted_docs = [payload.text]
        elif target.name == "email_agent":
            ctx.planted_emails = [{"from": "external.sender@mail.example", "subject": "Action required", "body": payload.text}]
        else:
            raise ValueError(f"{target.name} does not support indirect injection")
        user_turns = [payload.user_query or DEFAULT_INDIRECT_QUERY[target.name]]
    else:
        user_turns = payload.turns

    for user_text in user_turns:
        resp = target.run(user_text, ctx)
        turns.append(resp)
        verdicts.append(judge_attack(resp.observable_text, target.canary, resp.forbidden_tool_called))
        ctx.history += [{"role": "user", "content": user_text}, {"role": "assistant", "content": resp.text}]

    best = next((v for v in verdicts if v.success), verdicts[-1])
    return RunOutcome(payload.id, target.name, best, turns)


def run_benign(target: TargetApp, text: str) -> RunOutcome:
    """Run a legitimate prompt. ``verdict`` is still computed (a benign prompt must never leak)."""
    resp = target.run(text, RunContext())
    return RunOutcome("benign", target.name, judge_attack(resp.observable_text, target.canary, resp.forbidden_tool_called), [resp])


def record_outcome(db: Session, experiment_id: str, kind: str, defense: str, outcome: RunOutcome,
                   payload_id: str, category: str, vector: str, ood: bool) -> ExperimentResult:
    """Persist one run (result row + one ToolCall row per mock tool invocation)."""
    final = outcome.final
    row = ExperimentResult(
        experiment_id=experiment_id, kind=kind, target=outcome.target, defense=defense,
        payload_id=payload_id, category=category, vector=vector, ood=ood,
        success=outcome.verdict.success, canary_form=outcome.verdict.canary_hit.form,
        forbidden_tool=outcome.verdict.forbidden_tool, blocked=outcome.blocked, escalated=outcome.escalated,
        latency_ms=outcome.latency_ms, defense_latency_ms=outcome.defense_latency_ms, llm_calls=outcome.llm_calls,
        response_text=final.text[:4000], decisions=[d for t in outcome.turns for d in t.decisions][:50],
    )
    db.add(row)
    db.flush()
    for t in outcome.turns:
        for tc in t.tool_calls:
            db.add(ToolCall(experiment_id=experiment_id, result_id=row.id, target=outcome.target,
                            tool=tc.tool, arguments=tc.arguments, forbidden=tc.forbidden))
    return row
