"""Attack Lab backend: list targets and run ONE payload (or custom text) against a target with a chosen defense."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.schemas import RunRequest
from app.attacks.library import Payload, load_payloads
from app.attacks.runner import DEFAULT_INDIRECT_QUERY, run_attack
from app.core import audit
from app.core.config import get_settings
from app.core.rate_limit import enforce
from app.core.rbac import require_any, require_researcher
from app.db.models import DefenseConfig, TargetApp, User
from app.db.session import get_db
from app.defenses.registry import PRESETS, ConfigError, DefenseDeps, build_pipeline
from app.deps import get_defense_deps
from app.eval.canary import check_text
from app.llm.client import LLMError
from app.targets import TARGET_CLASSES, make_target

router = APIRouter(prefix="/targets", tags=["targets"])
DESCRIPTIONS = {
    "rag_bot": "Knowledge-base Q&A over 15 fake company documents; canary (API key) in the system prompt.",
    "email_agent": "Summarises an inbox and calls mock tools; transfer_credits and delete_record are forbidden.",
    "support_bot": "Customer-support bot guarding a confidential discount code (the canary).",
}


@router.get("")
def list_targets(db: Session = Depends(get_db), _: User = Depends(require_any)):
    rows = {t.name: t for t in db.scalars(select(TargetApp))}
    return [{"name": n, "kind": rows[n].kind if n in rows else "", "description": DESCRIPTIONS[n],
             "supports_indirect": cls.supports_indirect} for n, cls in TARGET_CLASSES.items()]


@router.post("/run")
def run_one(body: RunRequest, request: Request, db: Session = Depends(get_db), user: User = Depends(require_researcher),
            deps: DefenseDeps = Depends(get_defense_deps)):
    s = get_settings()
    enforce(f"run:user:{user.id}", s.experiment_user_limit)
    if body.target not in TARGET_CLASSES:
        raise HTTPException(404, "Unknown target")
    if bool(body.payload_id) == bool(body.custom_text):
        raise HTTPException(422, "Provide exactly one of payload_id or custom_text")

    if body.payload_id:
        payload = next((p for p in load_payloads() if p.id == body.payload_id), None)
        if payload is None:
            raise HTTPException(404, "Payload not found")
        if body.target not in payload.target_compat:
            raise HTTPException(422, f"Payload {payload.id} is not compatible with {body.target}")
    else:
        payload = Payload(id="custom", category="custom", technique="custom", vector=body.vector, text=body.custom_text or "",
                          multi_turn=None, target_compat=(body.target,), user_query=body.user_query)
    if payload.vector == "indirect" and not TARGET_CLASSES[body.target].supports_indirect:
        raise HTTPException(422, f"{body.target} does not support indirect injection")

    stages = _resolve_stages(db, user, body.defense, body.alpha)
    try:
        pipeline = build_pipeline(stages, deps, body.defense)
    except ConfigError as e:
        raise HTTPException(409, str(e))
    target = make_target(body.target, deps.llm, pipeline)  # fresh target => fresh random canary
    try:
        outcome = run_attack(target, payload)
    except LLMError as e:
        raise HTTPException(502, f"LLM backend error: {str(e)[:150]}")
    audit.append_event(db, "attack_lab_run", user.id, {"target": body.target, "payload": payload.id, "defense": body.defense,
                                                        "success": outcome.verdict.success})
    db.commit()
    turns = []
    for t in outcome.turns:
        hit = check_text(t.text, target.canary)  # spans are over the visible reply text only
        turns.append({"text": t.text, "blocked": t.blocked, "blocked_by": t.blocked_by, "decisions": t.decisions,
                      "tool_calls": [{"tool": c.tool, "arguments": c.arguments, "forbidden": c.forbidden, "result": c.result} for c in t.tool_calls],
                      "canary_spans": [list(sp) for sp in hit.spans], "latency_ms": round(t.latency_ms, 1)})
    return {"payload": {"id": payload.id, "category": payload.category, "text": payload.text, "turns": payload.turns},
            "success": outcome.verdict.success, "canary_leaked": outcome.verdict.canary_hit.found,
            "canary_form": outcome.verdict.canary_hit.form, "forbidden_tool_called": outcome.verdict.forbidden_tool,
            "blocked": outcome.blocked, "escalated": outcome.escalated, "llm_calls": outcome.llm_calls,
            "latency_ms": round(outcome.latency_ms, 1), "turns": turns}


def _resolve_stages(db: Session, user: User, name: str, alpha: float | None) -> dict:
    if name in PRESETS:
        stages = [dict(s) for s in PRESETS[name]]
        if alpha is not None:  # let the UI override alpha of any cascade stage
            for st in stages:
                if st["type"] == "cascade":
                    st["alpha"] = alpha
        return {"stages": stages}
    cfg = db.scalar(select(DefenseConfig).where(DefenseConfig.name == name, DefenseConfig.owner_id == user.id))
    if cfg is None:
        raise HTTPException(404, "Unknown defense")
    return cfg.config
