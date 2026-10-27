"""Authentication + role-based access control as FastAPI dependencies.

Authorization is enforced HERE, server-side, on every protected route. The frontend hides buttons
for convenience only - it is never the control.
"""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.security import decode_access_token
from app.db.models import Role, User
from app.db.session import get_db

ACCESS_COOKIE = "access_token"
REFRESH_COOKIE = "refresh_token"
CSRF_COOKIE = "csrf_token"


def get_current_user(request: Request, db: Session = Depends(get_db), settings: Settings = Depends(get_settings)) -> User:
    token = request.cookies.get(ACCESS_COOKIE)
    claims = decode_access_token(settings, token) if token else None
    if not claims:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    user = db.get(User, claims["sub"])
    # Re-read the user from the DB on every request: a deactivated/demoted user loses access
    # immediately instead of keeping a valid 15-minute JWT with stale claims.
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    return user


def require_roles(*roles: Role):
    """Dependency factory: allow only the listed roles."""
    allowed = {r.value for r in roles}

    def dep(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient permissions")
        return user

    return dep


require_admin = require_roles(Role.admin)
require_researcher = require_roles(Role.admin, Role.researcher)  # may run attacks/experiments
require_any = require_roles(Role.admin, Role.researcher, Role.viewer)
