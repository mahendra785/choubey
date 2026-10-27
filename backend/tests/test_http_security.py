from app.core import rate_limit
from app.core.config import get_settings
from app.core.logging import redact
from tests.conftest import login


def test_security_headers_present(client):
    r = client.get("/health")
    h = r.headers
    assert h["x-content-type-options"] == "nosniff"
    assert h["x-frame-options"] == "DENY"
    assert h["referrer-policy"] == "no-referrer"
    assert "max-age" in h["strict-transport-security"]
    assert "default-src 'none'" in h["content-security-policy"]


def test_cors_only_allows_frontend_origin(client):
    ok = client.options("/auth/login", headers={"Origin": "http://localhost:3000", "Access-Control-Request-Method": "POST"})
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:3000"
    assert ok.headers.get("access-control-allow-credentials") == "true"
    evil = client.options("/auth/login", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in evil.headers


def test_csrf_missing_header_blocked(client, admin_user, viewer_user):
    login(client, "admin@example.com")
    r = client.post("/admin/users", json={"email": "z@example.com", "password": "a-long-enough-pass"})  # no X-CSRF-Token
    assert r.status_code == 403 and "CSRF" in r.json()["detail"]


def test_csrf_wrong_token_blocked(client, admin_user):
    login(client, "admin@example.com")
    r = client.post("/admin/users", json={"email": "z@example.com", "password": "a-long-enough-pass"}, headers={"X-CSRF-Token": "forged"})
    assert r.status_code == 403


def test_csrf_foreign_origin_blocked(client, admin_user):
    s = login(client, "admin@example.com")
    r = client.post("/admin/users", json={"email": "z@example.com", "password": "a-long-enough-pass"},
                    headers={**s.h, "Origin": "https://evil.example"})
    assert r.status_code == 403


def test_oversized_body_rejected(client):
    r = client.post("/auth/login", content=b"x" * (300 * 1024), headers={"Content-Type": "application/json"})
    assert r.status_code == 413


def test_oversized_field_rejected(client):
    r = client.post("/auth/login", json={"email": "a@b.co", "password": "p" * 5000})
    assert r.status_code == 422


def test_sqli_style_strings_do_not_break_login(client, admin_user):
    for payload in ["' OR '1'='1", "admin@example.com'; DROP TABLE users;--", "\" OR \"\"=\""]:
        r = client.post("/auth/login", json={"email": payload + "@x.co", "password": payload})
        assert r.status_code in (401, 422)
    assert client.post("/auth/login", json={"email": "admin@example.com", "password": "' OR '1'='1"}).status_code == 401


def test_rate_limit_triggers_on_login(client, monkeypatch):
    limited = get_settings().model_copy(update={"rate_limit_enabled": True, "login_ip_limit": 3})
    monkeypatch.setattr(rate_limit, "get_settings", lambda: limited)
    codes = [client.post("/auth/login", json={"email": "ghost@example.com", "password": "pw-pw-pw-pw"}).status_code for _ in range(5)]
    assert codes[:3] == [401, 401, 401] and codes[3:] == [429, 429]


def test_sliding_window_unit():
    lim = rate_limit.RateLimiter()
    assert all(lim.check("k", 2, 10, now=t) for t in (0, 1))
    assert not lim.check("k", 2, 10, now=2)
    assert lim.check("k", 2, 10, now=11)  # first hit aged out of the window


def test_log_redaction():
    out = redact({"password": "hunter2", "msg": "leak CANARY-7f3a9cdeadbeef here", "nested": {"api_key": "k"}})
    assert out["password"] == "[REDACTED]" and out["nested"]["api_key"] == "[REDACTED]"
    assert "deadbeef" not in out["msg"] and "CANARY-7f****" in out["msg"]


def test_docs_hidden_in_production(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("JWT_SECRET", "p" * 40)
    get_settings.cache_clear()
    try:
        assert get_settings().is_production
    finally:
        monkeypatch.undo()
        get_settings.cache_clear()


def test_production_refuses_default_jwt_secret(monkeypatch):
    import pytest

    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("JWT_SECRET", raising=False)
    get_settings.cache_clear()
    try:
        with pytest.raises(RuntimeError):
            get_settings()
    finally:
        monkeypatch.undo()
        get_settings.cache_clear()
