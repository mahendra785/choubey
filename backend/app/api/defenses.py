"""Defense presets, user-defined pipeline configs, and detector status."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.schemas import DefenseConfigRequest
from app.core import audit
from app.core.rbac import require_any, require_researcher
from app.db.models import DefenseConfig, Role, User
from app.db.session import get_db
from app.defenses.registry import ALPHAS, PRESETS, ConfigError, DefenseDeps, preset_available, validate_config
from app.deps import get_defense_deps

router = APIRouter(prefix="/defenses", tags=["defenses"])


@router.get("/presets")
def presets(deps: DefenseDeps = Depends(get_defense_deps), _: User = Depends(require_any)):
    return [{"name": n, "stages": s, "available": preset_available(n, deps)} for n, s in PRESETS.items()]


@router.get("/detector")
def detector(deps: DefenseDeps = Depends(get_defense_deps), _: User = Depends(require_any)):
    return {"classifier": getattr(deps.classifier, "name", None), "calibration_n": None if deps.cal_labels is None else int(len(deps.cal_labels)),
            "alphas": ALPHAS, "llm_configured": deps.llm is not None}


@router.get("/configs")
def list_configs(db: Session = Depends(get_db), user: User = Depends(require_any)):
    q = select(DefenseConfig).order_by(DefenseConfig.created_at.desc())
    if user.role != Role.admin.value:
        q = q.where(DefenseConfig.owner_id == user.id)  # owners only (IDOR protection)
    return [{"id": c.id, "name": c.name, "config": c.config, "owner_id": c.owner_id} for c in db.scalars(q)]


@router.post("/configs", status_code=201)
def create_config(body: DefenseConfigRequest, db: Session = Depends(get_db), user: User = Depends(require_researcher)):
    if body.name in PRESETS:
        raise HTTPException(status.HTTP_409_CONFLICT, "Name clashes with a built-in preset")
    try:
        validate_config(body.config)
    except ConfigError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(e))
    cfg = DefenseConfig(name=body.name, owner_id=user.id, config=body.config)
    db.add(cfg)
    db.flush()
    audit.append_event(db, "defense_config_created", user.id, {"config_id": cfg.id, "name": body.name})
    db.commit()
    return {"id": cfg.id, "name": cfg.name, "config": cfg.config, "owner_id": cfg.owner_id}


@router.delete("/configs/{config_id}", status_code=204)
def delete_config(config_id: str, db: Session = Depends(get_db), user: User = Depends(require_researcher)):
    cfg = db.get(DefenseConfig, config_id)
    if cfg is None or (cfg.owner_id != user.id and user.role != Role.admin.value):
        raise HTTPException(404, "Not found")
    audit.append_event(db, "defense_config_deleted", user.id, {"config_id": cfg.id})
    db.delete(cfg)
    db.commit()
