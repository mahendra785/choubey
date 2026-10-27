from sqlalchemy import select, text

from app.core import audit
from app.db.models import AuditLog, User
from tests.conftest import PASSWORD, login


def test_unauthenticated_admin_routes_401(client):
    assert client.get("/admin/users").status_code == 401
    assert client.get("/admin/audit/verify").status_code == 401


def test_viewer_and_researcher_denied_admin(client, viewer_user, researcher_user):
    for email in ("viewer@example.com", "researcher@example.com"):
        s = login(client, email)
        assert s.get("/admin/users").status_code == 403
        assert s.get("/admin/audit/verify").status_code == 403
        assert s.post("/admin/users", json={"email": "x@y.co", "password": "a-long-enough-pass", "role": "admin"}).status_code == 403
        client.cookies.clear()


def test_admin_manages_users_and_role_change_is_audited(client, db, admin_user, viewer_user):
    s = login(client, "admin@example.com")
    r = s.post("/admin/users", json={"email": "New@Example.com", "password": "a-long-enough-pass", "role": "researcher"})
    assert r.status_code == 201 and r.json()["email"] == "new@example.com"
    assert s.post("/admin/users", json={"email": "new@example.com", "password": "a-long-enough-pass"}).status_code == 409
    r = s.patch(f"/admin/users/{viewer_user.id}/role", json={"role": "researcher"})
    assert r.status_code == 200 and r.json()["role"] == "researcher"
    actions = [row.action for row in db.scalars(select(AuditLog).order_by(AuditLog.seq))]
    assert "role_changed" in actions and "user_created" in actions
    assert s.patch(f"/admin/users/{admin_user.id}/role", json={"role": "viewer"}).status_code == 400  # no self-demotion


def test_privilege_escalation_via_body_is_rejected(client, viewer_user):
    s = login(client, "viewer@example.com")
    assert s.patch(f"/admin/users/{viewer_user.id}/role", json={"role": "admin"}).status_code == 403


def test_weak_password_rejected(client, admin_user):
    s = login(client, "admin@example.com")
    assert s.post("/admin/users", json={"email": "w@example.com", "password": "short"}).status_code == 422


def test_audit_chain_verifies(client, db, admin_user):
    s = login(client, "admin@example.com")
    client.post("/auth/login", json={"email": "admin@example.com", "password": "wrong-password-1"})
    r = s.get("/admin/audit/verify")
    assert r.status_code == 200 and r.json()["valid"] is True and r.json()["checked"] >= 2


def test_audit_chain_detects_modified_row(client, db, admin_user):
    s = login(client, "admin@example.com")
    client.post("/auth/login", json={"email": "admin@example.com", "password": "wrong-password-1"})
    # Manual DB tamper: an attacker rewrites history behind the application's back.
    db.execute(text("UPDATE audit_log SET action = 'nothing_to_see' WHERE seq = 1"))
    db.commit()
    r = s.get("/admin/audit/verify").json()
    assert r["valid"] is False and r["broken_at_seq"] == 1


def test_audit_chain_detects_deleted_row(client, db, admin_user):
    s = login(client, "admin@example.com")
    client.post("/auth/login", json={"email": "admin@example.com", "password": "wrong-password-1"})
    s.get("/admin/audit/verify")  # adds more rows
    db.execute(text("DELETE FROM audit_log WHERE seq = 2"))
    db.commit()
    r = s.get("/admin/audit/verify").json()
    assert r["valid"] is False


def test_audit_unit_empty_and_single(db):
    assert audit.verify_chain(db).valid
    audit.append_event(db, "x", None, {"a": 1})
    db.commit()
    res = audit.verify_chain(db)
    assert res.valid and res.checked == 1


def test_audit_never_stores_password(client, db, admin_user):
    client.post("/auth/login", json={"email": "admin@example.com", "password": PASSWORD})
    blob = " ".join(r.detail for r in db.scalars(select(AuditLog)))
    assert PASSWORD not in blob
    assert db.scalar(select(User).where(User.email == "admin@example.com")).password_hash.startswith("$argon2id$")
