"""Security headers + CSRF protection middleware."""
from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.core.rbac import ACCESS_COOKIE, CSRF_COOKIE, REFRESH_COOKIE
from app.core.security import tokens_match

_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
# Login has no session yet; every other state-changing request is checked.
_CSRF_EXEMPT_PATHS = {"/auth/login"}
_DOC_PATHS = ("/docs", "/openapi.json", "/redoc")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        h = response.headers
        h["X-Content-Type-Options"] = "nosniff"
        h["X-Frame-Options"] = "DENY"
        h["Referrer-Policy"] = "no-referrer"
        h["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        h["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        h["Cache-Control"] = "no-store"  # API responses can contain experiment data
        if not request.url.path.startswith(_DOC_PATHS):
            # This is a JSON API: it never needs to load or run anything.
            h["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        return response


class CSRFMiddleware(BaseHTTPMiddleware):
    """Double-submit-cookie CSRF check for cookie-authenticated, state-changing requests.

    The browser sends the csrf cookie automatically; JavaScript from OUR origin also copies it into
    the ``X-CSRF-Token`` header. A cross-site attacker can make the browser send the cookie but cannot
    read it, so cannot set the matching header. If an ``Origin`` header is present it must match too.
    """

    def __init__(self, app, allowed_origin: str) -> None:
        super().__init__(app)
        self.allowed_origin = allowed_origin

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.method not in _SAFE_METHODS and request.url.path not in _CSRF_EXEMPT_PATHS:
            uses_cookie_auth = ACCESS_COOKIE in request.cookies or REFRESH_COOKIE in request.cookies
            if uses_cookie_auth:
                origin = request.headers.get("origin")
                if origin is not None and origin != self.allowed_origin:
                    return JSONResponse({"detail": "Bad origin"}, status_code=403)
                if not tokens_match(request.cookies.get(CSRF_COOKIE), request.headers.get("x-csrf-token")):
                    return JSONResponse({"detail": "CSRF token missing or invalid"}, status_code=403)
        return await call_next(request)


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject oversized request bodies early (declared Content-Length) before parsing them."""

    def __init__(self, app, max_bytes: int = 256 * 1024) -> None:
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next) -> Response:
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > self.max_bytes:
            return JSONResponse({"detail": "Request body too large"}, status_code=413)
        return await call_next(request)
