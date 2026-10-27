"""Read-only access to the attack payload library."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from app.attacks.library import CATEGORIES, DEFAULT_OOD_CATEGORIES, Payload, load_payloads
from app.attacks.benign import benign_prompts
from app.core.rbac import require_any
from app.db.models import User

router = APIRouter(prefix="/attacks", tags=["attacks"])


def _out(p: Payload) -> dict:
    return {"id": p.id, "category": p.category, "technique": p.technique, "vector": p.vector, "text": p.text,
            "multi_turn": list(p.multi_turn) if p.multi_turn else None, "target_compat": list(p.target_compat),
            "user_query": p.user_query, "ood": p.is_ood}


@router.get("")
def list_attacks(category: str | None = Query(None, max_length=48), target: str | None = Query(None, max_length=48),
                 _: User = Depends(require_any)):
    return [_out(p) for p in load_payloads()
            if (not category or p.category == category) and (not target or target in p.target_compat)]


@router.get("/categories")
def categories(_: User = Depends(require_any)):
    return {"categories": CATEGORIES, "ood_categories": DEFAULT_OOD_CATEGORIES}


@router.get("/benign/{target}")
def benign_sample(target: str, n: int = Query(10, ge=1, le=50), _: User = Depends(require_any)):
    try:
        return [{"id": b.id, "text": b.text, "tricky": b.tricky} for b in benign_prompts(target, n)]
    except KeyError:
        raise HTTPException(404, "Unknown target")


@router.get("/{payload_id}")
def get_attack(payload_id: str, _: User = Depends(require_any)):
    for p in load_payloads():
        if p.id == payload_id:
            return _out(p)
    raise HTTPException(404, "Payload not found")
