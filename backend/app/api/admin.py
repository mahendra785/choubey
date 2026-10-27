"""Admin-only: user management and the audit log."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.schemas import AuditOut, AuditVerifyOut, ChangeRoleRequest, CreateUserRequest, SetActiveRequest, UserOut
from app.core import audit
from app.core.rbac import require_admin
from app.core.security import hash_password
from app.db.models import AuditLog, RefreshToken, User, utcnow
from app.db.session import get_db

router = APIRouter(prefix="/admin", tags=["admin"])


def _out(u: User) -> UserOut:
    return UserOut(id=u.id, email=u.email, role=u.role, is_active=u.is_active)


@router.get("/users", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), _: User = Depends(require_admin)):
    return [_out(u) for u in db.scalars(select(User).order_by(User.created_at))]


@router.post("/users", response_model=UserOut, status_code=201)
def create_user(body: CreateUserRequest, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    user = User(email=body.email, password_hash=hash_password(body.password), role=body.role)
    db.add(user)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")
    audit.append_event(db, "user_created", admin.id, {"user_id": user.id, "role": body.role})
    db.commit()
    return _out(user)


@router.patch("/users/{user_id}/role", response_model=UserOut)
def change_role(user_id: str, body: ChangeRoleRequest, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if user.id == admin.id:
        # Prevents the last admin from locking everyone out by accident.
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Admins cannot change their own role")
    old = user.role
    user.role = body.role
    audit.append_event(db, "role_changed", admin.id, {"user_id": user.id, "from": old, "to": body.role})
    db.commit()
    return _out(user)


@router.patch("/users/{user_id}/active", response_model=UserOut)
def set_active(user_id: str, body: SetActiveRequest, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if user.id == admin.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Admins cannot deactivate themselves")
    user.is_active = body.is_active
    if not body.is_active:  # deactivation also kills every refresh token
        db.execute(update(RefreshToken).where(RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_(None)).values(revoked_at=utcnow()))
    audit.append_event(db, "user_active_changed", admin.id, {"user_id": user.id, "is_active": body.is_active})
    db.commit()
    return _out(user)


@router.get("/audit", response_model=list[AuditOut])
def list_audit(limit: int = Query(100, ge=1, le=500), db: Session = Depends(get_db), _: User = Depends(require_admin)):
    rows = db.scalars(select(AuditLog).order_by(AuditLog.seq.desc()).limit(limit))
    return [AuditOut(seq=r.seq, ts=r.ts, actor_id=r.actor_id, action=r.action, detail=r.detail, hash=r.hash) for r in rows]


@router.get("/audit/verify", response_model=AuditVerifyOut)
def verify_audit(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    result = audit.verify_chain(db)
    audit.append_event(db, "audit_verified", admin.id, {"valid": result.valid, "checked": result.checked})
    db.commit()
    return AuditVerifyOut(valid=result.valid, checked=result.checked, broken_at_seq=result.broken_at_seq, reason=result.reason)
