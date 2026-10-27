from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db.models import RefreshToken, User, utcnow
from app.main import app
from tests.conftest import PASSWORD, login


def test_login_success_sets_hardened_cookies(client, admin_user):
    r = client.post("/auth/login", json={"email": "admin@example.com", "password": PASSWORD})
    assert r.status_code == 200
    body = r.json()
    assert body["user"]["role"] == "admin" and body["csrf_token"]
    cookies = r.headers.get_list("set-cookie")
    access = next(c for c in cookies if c.startswith("access_token="))
    refresh = next(c for c in cookies if c.startswith("refresh_token="))
    for c in (access, refresh):
        low = c.lower()
        assert "httponly" in low and "secure" in low and "samesite=strict" in low
    assert "path=/auth" in refresh.lower()  # refresh cookie scoped to /auth
    assert "password" not in r.text.lower()


def test_login_wrong_password_and_unknown_user_look_identical(client, admin_user):
    bad_pw = client.post("/auth/login", json={"email": "admin@example.com", "password": "nope-nope-nope"})
    unknown = client.post("/auth/login", json={"email": "ghost@example.com", "password": "nope-nope-nope"})
    assert bad_pw.status_code == unknown.status_code == 401
    assert bad_pw.json() == unknown.json()  # no user enumeration


def test_lockout_after_five_failures_then_expires(client, db, admin_user):
    for _ in range(5):
        assert client.post("/auth/login", json={"email": "admin@example.com", "password": "wrong-password-1"}).status_code == 401
    # Correct password is now refused because the account is locked.
    assert client.post("/auth/login", json={"email": "admin@example.com", "password": PASSWORD}).status_code == 401
    # Time-based: once locked_until passes, login works again.
    user = db.scalar(select(User).where(User.email == "admin@example.com"))
    user.locked_until = utcnow() - timedelta(seconds=1)
    db.commit()
    assert client.post("/auth/login", json={"email": "admin@example.com", "password": PASSWORD}).status_code == 200


def test_me_requires_auth(client):
    assert client.get("/auth/me").status_code == 401


def test_me_after_login(client, admin_user):
    login(client, "admin@example.com")
    assert client.get("/auth/me").json()["email"] == "admin@example.com"


def test_refresh_rotates_and_reuse_revokes_family(client, db, admin_user):
    s = login(client, "admin@example.com")
    old_refresh = client.cookies.get("refresh_token", path="/auth")
    r = s.post("/auth/refresh")
    assert r.status_code == 200
    new_refresh = client.cookies.get("refresh_token", path="/auth")
    assert new_refresh != old_refresh
    # Replaying the OLD token (as a thief would) fails AND burns the whole family.
    thief = TestClient(app, base_url="https://testserver")
    thief.cookies.set("refresh_token", old_refresh, path="/auth")
    thief.cookies.set("csrf_token", "t", path="/")
    r2 = thief.post("/auth/refresh", headers={"X-CSRF-Token": "t"})
    assert r2.status_code == 401
    live = db.scalars(select(RefreshToken).where(RefreshToken.revoked_at.is_(None))).all()
    assert live == []  # the legitimate user's rotated token was revoked too


def test_logout_revokes_refresh_token(client, db, admin_user):
    s = login(client, "admin@example.com")
    assert s.post("/auth/logout").status_code == 204
    assert db.scalars(select(RefreshToken).where(RefreshToken.revoked_at.is_(None))).all() == []


def test_expired_or_forged_jwt_rejected(client, admin_user):
    client.cookies.set("access_token", "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.", path="/")
    assert client.get("/auth/me").status_code == 401


def test_deactivated_user_loses_access_immediately(client, db, admin_user):
    login(client, "admin@example.com")
    user = db.scalar(select(User).where(User.email == "admin@example.com"))
    user.is_active = False
    db.commit()
    assert client.get("/auth/me").status_code == 401


def test_login_rejects_unknown_fields_and_bad_email(client):
    assert client.post("/auth/login", json={"email": "a@b.co", "password": "x", "is_admin": True}).status_code == 422
    assert client.post("/auth/login", json={"email": "not-an-email", "password": "x"}).status_code == 422
