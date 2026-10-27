"""Structured JSON logging with secret redaction.

Rule from the spec: never log passwords, tokens or full canaries. We enforce it in two
layers: (1) redact values of sensitive *keys*; (2) mask secret-looking *patterns* in free text.
"""
from __future__ import annotations

import json
import logging
import re
import sys
from datetime import datetime, timezone
from typing import Any

_SENSITIVE_KEYS = ("password", "token", "secret", "authorization", "cookie", "canary", "api_key")
# Canary tokens look like CANARY-<hex>; keep the prefix + 2 chars so logs stay debuggable.
_CANARY_RE = re.compile(r"(CANARY-[0-9a-fA-F]{2})[0-9a-fA-F]+")
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")


def redact(value: Any, key: str = "") -> Any:
    """Return a copy of ``value`` safe to log."""
    if any(k in key.lower() for k in _SENSITIVE_KEYS):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {k: redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v, key) for v in value]
    if isinstance(value, str):
        value = _JWT_RE.sub("[JWT]", value)
        return _CANARY_RE.sub(r"\1****", value)
    return value


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": redact(record.getMessage()),
        }
        extra = getattr(record, "fields", None)
        if isinstance(extra, dict):
            payload.update(redact(extra))
        if record.exc_info:
            payload["exc"] = redact(self.formatException(record.exc_info))
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())


def log_event(logger: logging.Logger, msg: str, **fields: Any) -> None:
    """Log ``msg`` with structured fields (they pass through ``redact``)."""
    logger.info(msg, extra={"fields": fields})
