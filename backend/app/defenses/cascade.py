"""Conformal-gated defense cascade - the project's core contribution.

    stage 1: fast classifier -> p = P(injection)
             Mondrian conformal prediction set C(x) at level alpha
                C = {benign}              -> ALLOW   (cheap, no LLM call)
                C = {injection}           -> BLOCK   (cheap, no LLM call)
                C = {benign, injection}   -> ESCALATE
                C = {}                    -> ESCALATE
    stage 2: LLM judge (slow, stronger) decides escalated cases only.

Why gate with conformal sets instead of a hand-picked probability band? The set is *calibrated*: for a
confident "allow" the chance that a true injection was wrongly allowed is bounded by alpha (see
conformal.py). The escalation rate then tells you exactly how much judge cost you pay for that guarantee.
Note the guarantee covers the classifier stage's decisions; the judge's own errors are not covered.
"""
from __future__ import annotations

from app.defenses.base import Action, Decision, Defense, DefenseContext, Timer
from app.defenses.classifier import InjectionClassifier, score_text
from app.defenses.conformal import BENIGN, INJECTION, MondrianConformal
from app.defenses.llm_judge import LLMJudge


def gate(pred_set: frozenset[int]) -> Action:
    """Map a conformal prediction set to an action."""
    if pred_set == frozenset({BENIGN}):
        return Action.allow
    if pred_set == frozenset({INJECTION}):
        return Action.block
    return Action.escalate


class ConformalCascade(Defense):
    name = "cascade"

    def __init__(self, clf: InjectionClassifier, conformal: MondrianConformal, judge: LLMJudge | None, alpha: float | None = None) -> None:
        self.clf, self.conformal, self.judge = clf, conformal, judge
        self.alpha = alpha if alpha is not None else conformal.alpha

    def inspect_input(self, text: str, source: str = "user", ctx: DefenseContext | None = None) -> Decision:
        with Timer() as t:
            p = score_text(self.clf, text)
            pred = self.conformal.predict_set(p)
            action = gate(pred)
        clf_ms = t.ms
        extra = {"p": p, "pred_set": sorted("injection" if y == INJECTION else "benign" for y in pred),
                 "alpha": self.alpha, "escalated": action is Action.escalate, "llm_calls": 0}
        if action is not Action.escalate:
            return Decision(action, p, f"conformal set {extra['pred_set']} at alpha={self.alpha}", clf_ms, self.name, extra=extra)
        if self.judge is None:
            return Decision(Action.escalate, p, "uncertain; no judge configured", clf_ms, self.name, extra=extra)
        jd = self.judge.inspect_input(text, source, ctx)
        extra.update(llm_calls=1, judge_action=jd.action.value, judge_reason=jd.reason)
        return Decision(jd.action, jd.score, f"escalated to judge: {jd.reason}", clf_ms + jd.latency_ms, self.name, extra=extra)
