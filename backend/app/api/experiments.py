"""Launch and read experiments.

Access rules (the IDOR defence): an experiment is visible to its owner and to admins; viewers (who cannot run
experiments) can read experiments the owner has explicitly marked `shared`. Anyone else gets 404 - not 403 - so the
existence of other users' experiment ids is not revealed.
"""
from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, sessionmaker

from app.api.schemas import ExperimentRequest, SharedRequest
from app.core import audit
from app.core.config import Settings, get_settings
from app.core.rate_limit import enforce
from app.core.rbac import require_any, require_researcher
from app.db.models import DefenseConfig, Experiment, ExperimentResult, Role, User
from app.db.session import get_db
from app.defenses.registry import ConfigError, DefenseDeps
from app.deps import get_defense_deps, get_session_factory
from app.eval import export
from app.eval.experiment import execute, resolve_defenses, row_dicts
from app.targets import TARGET_CLASSES

router = APIRouter(prefix="/experiments", tags=["experiments"])
log = logging.getLogger("promptshield.api")
_SAFE_NAME = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")


def _visible_query(user: User):
    q = select(Experiment)
    if user.role == Role.admin.value:
        return q
    if user.role == Role.researcher.value:
        return q.where(or_(Experiment.owner_id == user.id, Experiment.shared.is_(True)))
    return q.where(Experiment.shared.is_(True))


def _get_visible(db: Session, exp_id: str, user: User) -> Experiment:
    exp = db.scalar(_visible_query(user).where(Experiment.id == exp_id))
    if exp is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Experiment not found")
    return exp


def _brief(e: Experiment) -> dict:
    return {"id": e.id, "name": e.name, "kind": e.kind, "status": e.status, "shared": e.shared, "owner_id": e.owner_id,
            "total": e.total, "completed": e.completed, "model": e.model, "seed": e.seed,
            "created_at": e.created_at.isoformat(), "finished_at": e.finished_at.isoformat() if e.finished_at else None, "error": e.error}


@router.get("")
def list_experiments(kind: str | None = Query(None, max_length=24), limit: int = Query(50, ge=1, le=200),
                     db: Session = Depends(get_db), user: User = Depends(require_any)):
    q = _visible_query(user).order_by(Experiment.created_at.desc()).limit(limit)
    if kind:
        q = q.where(Experiment.kind == kind)
    return [_brief(e) for e in db.scalars(q)]


@router.post("", status_code=202)
def create_experiment(body: ExperimentRequest, background: BackgroundTasks, db: Session = Depends(get_db),
                      user: User = Depends(require_researcher), settings: Settings = Depends(get_settings),
                      deps: DefenseDeps = Depends(get_defense_deps), factory: sessionmaker = Depends(get_session_factory)):
    enforce(f"experiment:user:{user.id}", settings.experiment_user_limit)
    unknown = [t for t in body.targets if t not in TARGET_CLASSES]
    if unknown:
        raise HTTPException(422, f"unknown targets: {unknown}")
    defenses = None
    config = body.model_dump()
    if body.kind == "end_to_end":
        custom = {c.name: c.config for c in db.scalars(select(DefenseConfig).where(DefenseConfig.owner_id == user.id))}
        try:
            defenses = resolve_defenses(body.defenses, custom, deps)
        except ConfigError as e:
            raise HTTPException(409, str(e))
        config["defense_stages"] = defenses  # store resolved stages => the run is reproducible later
    exp = Experiment(owner_id=user.id, name=body.name, kind=body.kind, config=config, seed=body.seed, status="queued",
                     model=getattr(deps.llm, "model", "") if body.kind == "end_to_end" else getattr(deps.classifier, "name", ""))
    db.add(exp)
    db.flush()
    audit.append_event(db, "experiment_run", user.id, {"experiment_id": exp.id, "kind": body.kind, "targets": body.targets,
                                                       "defenses": body.defenses, "seed": body.seed})
    db.commit()
    background.add_task(_run_job, exp.id, factory, settings, deps, defenses)
    return _brief(exp)


def _run_job(exp_id: str, factory: sessionmaker, settings: Settings, deps: DefenseDeps, defenses) -> None:
    with factory() as db:
        exp = db.get(Experiment, exp_id)
        execute(db, exp, settings, deps.llm, deps, defenses)
        exp = db.get(Experiment, exp_id)
        if exp.status == "done":
            try:
                out = Path(settings.results_dir) / exp.id
                meta = {"run_id": exp.id, "model": exp.model, "seed": exp.seed}
                if exp.kind == "conformal_sweep":
                    export.export_conformal(exp.summary, out, meta)
                else:
                    export.export_end_to_end(exp.summary, row_dicts(db, exp.id), out, meta)
            except Exception:  # noqa: BLE001 - an export problem must not turn a finished experiment into a failure
                log.exception("export failed for %s", exp.id)


@router.get("/{exp_id}")
def get_experiment(exp_id: str, db: Session = Depends(get_db), user: User = Depends(require_any)):
    exp = _get_visible(db, exp_id, user)
    return {**_brief(exp), "config": {k: v for k, v in exp.config.items() if k != "defense_stages"}, "summary": exp.summary}


@router.get("/{exp_id}/results")
def get_results(exp_id: str, limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0, le=1_000_000),
                kind: str | None = Query(None, pattern="^(attack|benign)$"), db: Session = Depends(get_db), user: User = Depends(require_any)):
    _get_visible(db, exp_id, user)
    q = select(ExperimentResult).where(ExperimentResult.experiment_id == exp_id).order_by(ExperimentResult.id).limit(limit).offset(offset)
    if kind:
        q = q.where(ExperimentResult.kind == kind)
    total = db.scalar(select(func.count()).select_from(ExperimentResult).where(ExperimentResult.experiment_id == exp_id))
    return {"total": total, "items": [{
        "id": r.id, "kind": r.kind, "target": r.target, "defense": r.defense, "payload_id": r.payload_id, "category": r.category,
        "vector": r.vector, "ood": r.ood, "success": r.success, "canary_form": r.canary_form, "forbidden_tool": r.forbidden_tool,
        "blocked": r.blocked, "escalated": r.escalated, "latency_ms": round(r.latency_ms, 1), "llm_calls": r.llm_calls,
        "response_text": r.response_text, "decisions": r.decisions} for r in db.scalars(q)]}


@router.patch("/{exp_id}/shared")
def set_shared(exp_id: str, body: SharedRequest, db: Session = Depends(get_db), user: User = Depends(require_researcher)):
    exp = _get_visible(db, exp_id, user)
    if exp.owner_id != user.id and user.role != Role.admin.value:
        raise HTTPException(404, "Experiment not found")
    exp.shared = body.shared
    audit.append_event(db, "experiment_shared_changed", user.id, {"experiment_id": exp.id, "shared": body.shared})
    db.commit()
    return _brief(exp)


@router.get("/{exp_id}/files")
def list_files(exp_id: str, db: Session = Depends(get_db), user: User = Depends(require_any), settings: Settings = Depends(get_settings)):
    _get_visible(db, exp_id, user)
    d = Path(settings.results_dir) / exp_id
    return sorted(p.name for p in d.iterdir() if p.is_file()) if d.is_dir() else []


@router.get("/{exp_id}/files/{name}")
def download_file(exp_id: str, name: str, db: Session = Depends(get_db), user: User = Depends(require_any),
                  settings: Settings = Depends(get_settings)):
    _get_visible(db, exp_id, user)
    # Path traversal defence: whitelist characters and require the resolved path to stay inside the experiment's folder.
    if not name or not set(name) <= _SAFE_NAME or name.startswith("."):
        raise HTTPException(400, "Bad file name")
    base = (Path(settings.results_dir) / exp_id).resolve()
    target = (base / name).resolve()
    if base not in target.parents or not target.is_file():
        raise HTTPException(404, "File not found")
    return FileResponse(target, filename=name)
