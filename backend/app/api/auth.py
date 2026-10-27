"""Login, refresh-token rotation, logout, whoami."""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.api.schemas import LoginRequest, LoginResponse, UserOut
from app.core import audit
from app.core.config import Settings, get_settings
from app.core.rate_limit import client_ip, enforce, limit_by_ip
from app.core.rbac import ACCESS_COOKIE, CSRF_COOKIE, REFRESH_COOKIE, get_current_user
from app.core.security import (
    create_access_token,
    hash_password,
    hash_token,
    new_csrf_token,
    new_opaque_token,
    password_needs_rehash,
    verify_password,
)
from app.db.models import RefreshToken, User, as_utc, new_id, utcnow
from app.db.session import get_db

router = APIRouter(prefix="/auth", tags=["auth"])

_GENERIC_FAIL = "Invalid credentials or account locked"


def _user_out(u: User) -> UserOut:
    return UserOut(id=u.id, email=u.email, role=u.role, is_active=u.is_active)


def _set_session_cookies(response: Response, settings: Settings, user: User, refresh_plain: str) -> str:
    """Set access, refresh and CSRF cookies. Returns the CSRF token (also given to the SPA in the body)."""
    common = {"secure": settings.cookie_secure, "samesite": "strict"}
    response.set_cookie(
        ACCESS_COOKIE, create_access_token(settings, user.id, user.role), httponly=True,
        max_age=settings.access_token_minutes * 60, path="/", **common,
    )
    # The refresh token is only ever needed by /auth/*, so its cookie is scoped to that path.
    response.set_cookie(
        REFRESH_COOKIE, refresh_plain, httponly=True,
        max_age=settings.refresh_token_days * 86400, path="/auth", **common,
    )
    csrf = new_csrf_token()
    # NOT httpOnly: the SPA must read it to echo it in the X-CSRF-Token header (double-submit).
    response.set_cookie(CSRF_COOKIE, csrf, httponly=False, max_age=settings.refresh_token_days * 86400, path="/", **common)
    return csrf


def _clear_cookies(response: Response) -> None:
    response.delete_cookie(ACCESS_COOKIE, path="/")
    response.delete_cookie(REFRESH_COOKIE, path="/auth")
    response.delete_cookie(CSRF_COOKIE, path="/")


def _issue_refresh(db: Session, settings: Settings, user_id: str, family_id: str | None = None) -> str:
    plain = new_opaque_token()
    db.add(RefreshToken(
        user_id=user_id, token_hash=hash_token(plain), family_id=family_id or new_id(),
        expires_at=utcnow() + timedelta(days=settings.refresh_token_days),
    ))
    return plain


def _revoke_family(db: Session, family_id: str) -> None:
    db.execute(update(RefreshToken).where(RefreshToken.family_id == family_id, RefreshToken.revoked_at.is_(None)).values(revoked_at=utcnow()))


@router.post("/login", response_model=LoginResponse, dependencies=[Depends(limit_by_ip("login"))])
def login(body: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db), settings: Settings = Depends(get_settings)):
    # Second limiter keyed on the (hashed) e-mail so one account cannot be hammered from many IPs.
    enforce("login:user:" + hashlib.sha256(body.email.encode()).hexdigest(), settings.login_user_limit)
    ip = client_ip(request)
    user = db.scalar(select(User).where(User.email == body.email))
    now = utcnow()

    if user and user.locked_until and as_utc(user.locked_until) > now:
        audit.append_event(db, "login_blocked_locked", user.id, {"ip": ip})
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, _GENERIC_FAIL)

    # verify_password burns equal time when the user does not exist (user enumeration defence).
    ok = verify_password(user.password_hash if user else None, body.password)
    if not (user and user.is_active and ok):
        if user:
            user.failed_attempts += 1
            locked = user.failed_attempts >= settings.max_failed_logins
            if locked:
                user.locked_until = now + timedelta(minutes=settings.lockout_minutes)
                user.failed_attempts = 0
            audit.append_event(db, "login_failed", user.id, {"ip": ip, "locked": locked})
        else:
            audit.append_event(db, "login_failed_unknown_user", None, {"ip": ip})
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, _GENERIC_FAIL)

    user.failed_attempts = 0
    user.locked_until = None
    if password_needs_rehash(user.password_hash):  # transparently upgrade old hash parameters
        user.password_hash = hash_password(body.password)
    refresh = _issue_refresh(db, settings, user.id)
    audit.append_event(db, "login_success", user.id, {"ip": ip})
    db.commit()
    csrf = _set_session_cookies(response, settings, user, refresh)
    return LoginResponse(user=_user_out(user), csrf_token=csrf)


@router.post("/refresh", response_model=LoginResponse, dependencies=[Depends(limit_by_ip("refresh"))])
def refresh(request: Request, response: Response, db: Session = Depends(get_db), settings: Settings = Depends(get_settings)):
    """Rotate the refresh token. Presenting an already-used token revokes the whole family."""
    plain = request.cookies.get(REFRESH_COOKIE)
    row = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == hash_token(plain))) if plain else None
    if row is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid refresh token")
    if row.revoked_at is not None:
        # Re-use of a rotated token = likely theft. Kill every token descended from this login.
        _revoke_family(db, row.family_id)
        audit.append_event(db, "refresh_reuse_detected", row.user_id, {"family": row.family_id})
        db.commit()
        _clear_cookies(response)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid refresh token")
    user = db.get(User, row.user_id)
    if as_utc(row.expires_at) <= utcnow() or user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid refresh token")
    row.revoked_at = utcnow()
    new_plain = _issue_refresh(db, settings, user.id, family_id=row.family_id)
    audit.append_event(db, "token_refreshed", user.id, {})
    db.commit()
    csrf = _set_session_cookies(response, settings, user, new_plain)
    return LoginResponse(user=_user_out(user), csrf_token=csrf)


@router.post("/logout", status_code=204)
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    plain = request.cookies.get(REFRESH_COOKIE)
    row = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == hash_token(plain))) if plain else None
    if row:
        _revoke_family(db, row.family_id)
        audit.append_event(db, "logout", row.user_id, {})
        db.commit()
    _clear_cookies(response)
    response.status_code = 204
    return response


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return _user_out(user)
