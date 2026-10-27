"""Sliding-window rate limiter (in-memory, per process).

Single-process is enough for this testbed. A multi-replica deployment would need a shared store
(e.g. Redis) - noted in THREAT_MODEL.md. Keys combine a bucket name with an IP or user id, giving
the per-IP and per-user limits the spec asks for.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request, status

from app.core.config import get_settings


class RateLimiter:
    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, limit: int, window_s: float, now: float | None = None) -> bool:
        """Record a hit; return False if ``key`` exceeded ``limit`` hits within ``window_s``."""
        now = time.monotonic() if now is None else now
        with self._lock:
            q = self._hits[key]
            while q and q[0] <= now - window_s:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


limiter = RateLimiter()


def client_ip(request: Request) -> str:
    # We deliberately do NOT trust X-Forwarded-For: any client could spoof it to dodge the limit.
    return request.client.host if request.client else "unknown"


def enforce(key: str, limit: int) -> None:
    s = get_settings()
    if not s.rate_limit_enabled:
        return
    if not limiter.check(key, limit, s.rate_window_seconds):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many requests", headers={"Retry-After": str(s.rate_window_seconds)})


def limit_by_ip(bucket: str, limit: int | None = None):
    """Dependency factory: limit a route per client IP."""

    def dep(request: Request) -> None:
        enforce(f"{bucket}:ip:{client_ip(request)}", limit or get_settings().login_ip_limit)

    return dep
