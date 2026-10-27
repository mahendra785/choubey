"""FastAPI entrypoint: wires middleware (security headers, CSRF, CORS) and routers."""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.core.middleware import BodySizeLimitMiddleware, CSRFMiddleware, SecurityHeadersMiddleware

settings = get_settings()
configure_logging(settings.log_level)

app = FastAPI(
    title="PromptShield",
    version="0.8.0",
    # Interactive API docs are a recon aid; expose them outside production only.
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None,
    openapi_url=None if settings.is_production else "/openapi.json",
)

# Starlette runs the LAST added middleware FIRST (outermost). CORS must be outermost so that
# preflight requests and even our own 403/413 error responses carry the CORS headers.
app.add_middleware(BodySizeLimitMiddleware)
app.add_middleware(CSRFMiddleware, allowed_origin=settings.frontend_origin)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin],  # exactly one origin, never "*", because we use credentials
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Content-Type", "X-CSRF-Token"],
)

from app.api import admin, attacks, auth, defenses, experiments, targets  # noqa: E402

app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(targets.router)
app.include_router(attacks.router)
app.include_router(defenses.router)
app.include_router(experiments.router)


@app.get("/health", tags=["meta"])
def health() -> dict[str, str]:
    """Liveness probe. Deliberately does not touch the DB so it stays cheap and dependency-free."""
    return {"status": "ok", "version": app.version}
