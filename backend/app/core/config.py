"""Application settings, read from environment variables only.

Why env-only: secrets must never live in code or in the repo (see SECURE CODING
REQUIREMENTS). We use a plain frozen Pydantic model instead of an extra settings
library so the dependency list stays small.
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, ConfigDict

_DEV_JWT_SECRET = "dev-only-insecure-secret-change-me-0123456789"


class Settings(BaseModel):
    # frozen: settings are immutable after startup; forbid: typos in field names fail loudly.
    model_config = ConfigDict(frozen=True, extra="forbid")

    app_env: str = "development"
    log_level: str = "INFO"
    database_url: str = "postgresql+psycopg://promptshield:promptshield@localhost:5432/promptshield"
    frontend_origin: str = "http://localhost:3000"

    # --- auth ---
    jwt_secret: str = _DEV_JWT_SECRET
    access_token_minutes: int = 15
    refresh_token_days: int = 7
    max_failed_logins: int = 5
    lockout_minutes: int = 15
    cookie_secure: bool = True
    admin_email: str = ""
    admin_password: str = ""

    # --- rate limiting (requests per window; window in seconds) ---
    rate_limit_enabled: bool = True
    login_ip_limit: int = 20
    login_user_limit: int = 10
    experiment_user_limit: int = 20
    rate_window_seconds: int = 60

    # --- LLM (OpenAI-compatible) ---
    llm_base_url: str = "http://localhost:11434/v1"
    llm_api_key: str = "ollama"
    llm_model: str = "qwen2.5:7b-instruct"
    llm_temperature: float = 0.0
    llm_seed: int = 1234
    llm_timeout_s: float = 120.0

    # --- ML artifacts / outputs ---
    artifacts_dir: str = "ml/artifacts"
    results_dir: str = "results"

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    return default if raw is None else raw.strip().lower() in {"1", "true", "yes", "on"}


def _repo_root() -> Path:
    # backend/app/core/config.py -> repo root is three parents above "app"
    return Path(__file__).resolve().parents[3]


@lru_cache
def get_settings() -> Settings:
    """Build settings once per process from the environment."""
    env = os.environ.get
    app_env = env("APP_ENV", "development")
    jwt_secret = env("JWT_SECRET", _DEV_JWT_SECRET)
    if app_env == "production" and jwt_secret == _DEV_JWT_SECRET:
        # Refuse to boot with the well-known development secret in production.
        raise RuntimeError("JWT_SECRET must be set in production")
    root = _repo_root()
    return Settings(
        app_env=app_env,
        log_level=env("LOG_LEVEL", "INFO"),
        database_url=env(
            "DATABASE_URL",
            "postgresql+psycopg://promptshield:promptshield@localhost:5432/promptshield",
        ),
        frontend_origin=env("FRONTEND_ORIGIN", "http://localhost:3000"),
        jwt_secret=jwt_secret,
        cookie_secure=_env_bool("COOKIE_SECURE", True),
        admin_email=env("ADMIN_EMAIL", ""),
        admin_password=env("ADMIN_PASSWORD", ""),
        rate_limit_enabled=_env_bool("RATE_LIMIT_ENABLED", True),
        llm_base_url=env("LLM_BASE_URL", "http://localhost:11434/v1"),
        llm_api_key=env("LLM_API_KEY", "ollama"),
        llm_model=env("LLM_MODEL", "qwen2.5:7b-instruct"),
        llm_temperature=float(env("LLM_TEMPERATURE", "0")),
        llm_seed=int(env("LLM_SEED", "1234")),
        llm_timeout_s=float(env("LLM_TIMEOUT_S", "120")),
        artifacts_dir=env("ARTIFACTS_DIR", str(root / "ml" / "artifacts")),
        results_dir=env("RESULTS_DIR", str(root / "results")),
    )
