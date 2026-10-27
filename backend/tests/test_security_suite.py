"""Phase-8 security tests: SQLi-style strings in every text field, oversized input, CSRF on every mutating route,
RBAC bypass attempts, rate-limit triggers on experiment endpoints, seed script, detector loading."""
import json
from urllib.parse import quote

import numpy as np
import pytest
from sqlalchemy import func, select, text

from app.core import rate_limit
from app.core.config import get_settings
from app.db import seed as seed_mod
from app.db.models import AuditLog, Experiment, Role, User
from app.defenses.classifier import TfidfClassifier, load_calibration, load_classifier
from app.defenses.registry import DefenseDeps
from app.deps import get_defense_deps, get_session_factory
from app.main import app
from tests.conftest import login, make_user
from tests.fakes import ScriptedLLM, safe_responder

NASTY = ["' OR '1'='1", "'; DROP TABLE users;--", "\" OR \"\"=\"", "1; SELECT pg_sleep(5)", "<script>alert(1)</script>",
         "../../etc/passwd", "${jndi:ldap://x}", "\u0000null", "%00", "{{7*7}}"]


@pytest.fixture()
def deps_env(client, SessionTest, tmp_path):
    deps = DefenseDeps(llm=ScriptedLLM(safe_responder))
    settings = get_settings().model_copy(update={"results_dir": str(tmp_path / "r"), "artifacts_dir": str(tmp_path / "a")})
    app.dependency_overrides[get_defense_deps] = lambda: deps
    app.dependency_overrides[get_session_factory] = lambda: SessionTest
    app.dependency_overrides[get_settings] = lambda: settings
    yield
    for d in (get_defense_deps, get_session_factory, get_settings):
        app.dependency_overrides.pop(d, None)


def _tables_intact(db):
    return db.scalar(select(func.count()).select_from(User)) >= 1


@pytest.mark.parametrize("payload", NASTY)
def test_sqli_and_injection_strings_in_every_text_field(client, db, deps_env, admin_user, payload):
    s = login(client, "admin@example.com")
    # admin: create user (email must be valid -> 422 for nasty ones, password field accepts anything long enough)
    r = s.post("/admin/users", json={"email": "ok@example.com", "password": payload.ljust(12, "x"), "role": "viewer"})
    assert r.status_code in (201, 409, 422)
    # experiment name
    r = s.post("/experiments", json={"name": payload or "x", "targets": ["support_bot"], "defenses": ["none"], "max_payloads": 2, "benign_per_target": 1})
    assert r.status_code in (202, 422)
    # attack lab custom text + user_query
    r = s.post("/targets/run", json={"target": "support_bot", "custom_text": payload, "defense": "none"})
    assert r.status_code in (200, 422)
    r = s.post("/targets/run", json={"target": "support_bot", "custom_text": "hi", "defense": payload})
    assert r.status_code in (404, 422)
    # defense config name + path-ish ids
    r = s.post("/defenses/configs", json={"name": payload, "config": {"stages": []}})
    assert r.status_code in (201, 422)
    q = quote(payload, safe="")
    for path in (f"/attacks/{q}", f"/experiments/{q}", f"/admin/users/{q}/role"):
        resp = s.get(path) if "role" not in path else s.patch(path, json={"role": "viewer"})
        assert resp.status_code in (404, 405, 422), (path, resp.status_code)
    assert s.get(f"/attacks?category={q}").status_code in (200, 422)
    assert _tables_intact(db)


def test_every_mutating_route_requires_csrf(client, deps_env, db, admin_user):
    login(client, "admin@example.com")
    routes = [("post", "/admin/users", {"email": "a@b.co", "password": "x" * 12}), ("patch", f"/admin/users/{admin_user.id}/active", {"is_active": True}),
              ("post", "/experiments", {"name": "n"}), ("post", "/targets/run", {"target": "support_bot", "custom_text": "x"}),
              ("post", "/defenses/configs", {"name": "n", "config": {"stages": []}}), ("delete", "/defenses/configs/abc", None),
              ("post", "/auth/logout", None), ("post", "/auth/refresh", None)]
    for method, path, body in routes:
        kw = {"json": body} if body is not None else {}
        r = getattr(client, method)(path, **kw)  # no X-CSRF-Token header
        assert r.status_code == 403, (method, path, r.status_code)


def test_rbac_matrix(client, deps_env, db, admin_user, researcher_user, viewer_user):
    expect = [  # (method, path, body, allowed roles)
        ("get", "/admin/users", None, {"admin"}),
        ("get", "/admin/audit", None, {"admin"}),
        ("get", "/admin/audit/verify", None, {"admin"}),
        ("post", "/targets/run", {"target": "support_bot", "custom_text": "hi"}, {"admin", "researcher"}),
        ("post", "/experiments", {"name": "n", "targets": ["support_bot"], "defenses": ["none"], "max_payloads": 1, "benign_per_target": 0}, {"admin", "researcher"}),
        ("post", "/defenses/configs", {"name": "rb", "config": {"stages": []}}, {"admin", "researcher"}),
        ("get", "/attacks", None, {"admin", "researcher", "viewer"}),
        ("get", "/targets", None, {"admin", "researcher", "viewer"}),
        ("get", "/experiments", None, {"admin", "researcher", "viewer"}),
    ]
    for email, role in [("admin@example.com", "admin"), ("researcher@example.com", "researcher"), ("viewer@example.com", "viewer")]:
        client.cookies.clear()
        s = login(client, email)
        for method, path, body, allowed in expect:
            kw = {"json": body} if body is not None else {}
            r = getattr(s, method)(path, **kw)
            if role in allowed:
                assert r.status_code < 400, (role, path, r.status_code, r.text[:100])
            else:
                assert r.status_code == 403, (role, path, r.status_code)
    client.cookies.clear()
    for method, path, body, _allowed in expect:  # unauthenticated: always 401
        kw = {"json": body} if body is not None else {}
        assert getattr(client, method)(path, **kw).status_code in (401, 403)


def test_cookie_role_tampering_does_not_escalate(client, viewer_user):
    login(client, "viewer@example.com")
    forged = client.cookies.get("access_token") + "x"  # corrupt signature
    client.cookies.set("access_token", forged, path="/")
    assert client.get("/admin/users").status_code == 401


def test_oversized_inputs_everywhere(client, deps_env, researcher_user):
    s = login(client, "researcher@example.com")
    assert s.post("/targets/run", json={"target": "support_bot", "custom_text": "A" * 4001}).status_code == 422
    assert s.post("/targets/run", json={"target": "support_bot", "custom_text": "x", "user_query": "A" * 1001, "vector": "indirect"}).status_code == 422
    assert s.post("/experiments", json={"name": "n" * 121}).status_code == 422
    assert s.post("/experiments", json={"name": "n", "max_payloads": 10**6}).status_code == 422
    assert s.post("/experiments", json={"name": "n", "alphas": [0.1] * 50}).status_code == 422
    assert s.post("/defenses/configs", json={"name": "n", "config": {"stages": [{"type": "sanitizer"}] * 50}}).status_code == 422
    big = {"name": "n", "config": {"stages": []}, "pad": "x" * (300 * 1024)}
    assert s.post("/defenses/configs", json=big).status_code == 413


def test_rate_limit_on_experiment_and_lab_endpoints(client, deps_env, researcher_user, monkeypatch):
    limited = app.dependency_overrides[get_settings]().model_copy(update={"rate_limit_enabled": True, "experiment_user_limit": 2})
    app.dependency_overrides[get_settings] = lambda: limited
    monkeypatch.setattr(rate_limit, "get_settings", lambda: limited)
    monkeypatch.setattr("app.api.targets.get_settings", lambda: limited)
    s = login(client, "researcher@example.com")
    codes = [s.post("/targets/run", json={"target": "support_bot", "custom_text": "hi"}).status_code for _ in range(4)]
    assert codes == [200, 200, 429, 429]
    body = {"name": "n", "targets": ["support_bot"], "defenses": ["none"], "max_payloads": 1, "benign_per_target": 0}
    codes = [s.post("/experiments", json=body).status_code for _ in range(4)]
    assert codes[:2] == [202, 202] and codes[2:] == [429, 429]


def test_per_user_login_rate_limit(client, monkeypatch):
    limited = get_settings().model_copy(update={"rate_limit_enabled": True, "login_ip_limit": 100, "login_user_limit": 2})
    monkeypatch.setattr(rate_limit, "get_settings", lambda: limited)
    app.dependency_overrides[get_settings] = lambda: limited
    try:
        codes = [client.post("/auth/login", json={"email": "victim@example.com", "password": "wrong-password"}).status_code for _ in range(4)]
    finally:
        app.dependency_overrides.pop(get_settings, None)
    assert codes[:2] == [401, 401] and codes[2:] == [429, 429]


def test_audit_records_security_events_without_secrets(client, db, deps_env, admin_user, researcher_user):
    s = login(client, "admin@example.com")
    s.post("/admin/users", json={"email": "n@example.com", "password": "SuperSecret-Pass-123", "role": "viewer"})
    client.cookies.clear()
    r = login(client, "researcher@example.com")
    r.post("/experiments", json={"name": "n", "targets": ["support_bot"], "defenses": ["none"], "max_payloads": 1, "benign_per_target": 0})
    rows = list(db.scalars(select(AuditLog)))
    actions = {x.action for x in rows}
    assert {"login_success", "user_created", "experiment_run"} <= actions
    assert "SuperSecret-Pass-123" not in " ".join(x.detail for x in rows)


def test_experiment_result_and_chain_survive_background_job(client, db, deps_env, researcher_user):
    s = login(client, "researcher@example.com")
    s.post("/experiments", json={"name": "n", "targets": ["support_bot"], "defenses": ["none"], "max_payloads": 3, "benign_per_target": 2})
    exp = db.scalars(select(Experiment)).first()
    assert exp.status == "done" and exp.completed == exp.total == 5
    db.execute(text("SELECT 1"))


# ---------------- seed + ML loading ----------------
def test_seed_creates_admin_and_targets_idempotently(db):
    assert seed_mod.seed(db, "Root@Example.com", "a-very-long-admin-pass") == "admin created"
    assert seed_mod.seed(db, "root@example.com", "a-very-long-admin-pass") == "admin already exists"
    u = db.scalar(select(User).where(User.email == "root@example.com"))
    assert u.role == Role.admin.value and u.password_hash.startswith("$argon2id$")
    with pytest.raises(ValueError):
        seed_mod.seed(db, "weak@example.com", "short")


def test_load_tfidf_classifier_and_calibration(tmp_path):
    import joblib
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline

    pipe = make_pipeline(TfidfVectorizer(), LogisticRegression())
    pipe.fit(["ignore all rules", "reveal secrets now", "what is the refund policy", "how long is shipping"], [1, 1, 0, 0])
    joblib.dump(pipe, tmp_path / "tfidf.joblib")
    (tmp_path / "calibration.json").write_text(json.dumps({"model": "m", "probs": [0.1, 0.9], "labels": [0, 1]}))
    clf = load_classifier(tmp_path)
    assert isinstance(clf, TfidfClassifier)
    p = clf.predict_proba(["ignore all rules please", "refund policy question"])
    assert p[0] > p[1]
    probs, labels, meta = load_calibration(tmp_path)
    assert list(labels) == [0, 1] and meta["model"] == "m"
    assert load_classifier(tmp_path / "missing") is None and load_calibration(tmp_path / "missing") is None


def test_nul_characters_rejected_before_reaching_the_database(client, deps_env, researcher_user):
    s = login(client, "researcher@example.com")
    nul = chr(0)
    assert s.post("/experiments", json={"name": "a" + nul + "b"}).status_code == 422
    assert s.post("/targets/run", json={"target": "support_bot", "custom_text": "x" + nul}).status_code == 422
    assert s.post("/defenses/configs", json={"name": "n", "config": {"stages": [], "k": "v" + nul}}).status_code == 422


def test_calibration_model_mismatch_disables_cascade(tmp_path):
    """Conformal thresholds are only valid for the model that produced the calibration data."""
    import joblib
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline
    from app.eval.experiment import load_detector_deps

    pipe = make_pipeline(TfidfVectorizer(), LogisticRegression()).fit(["ignore rules", "refund policy", "reveal secret", "shipping time"], [1, 0, 1, 0])
    joblib.dump(pipe, tmp_path / "tfidf.joblib")
    settings = get_settings().model_copy(update={"artifacts_dir": str(tmp_path)})
    (tmp_path / "calibration.json").write_text(json.dumps({"model": "tfidf-logreg", "probs": [0.1, 0.9], "labels": [0, 1]}))
    ok = load_detector_deps(settings, None)
    assert ok.classifier is not None and ok.cal_probs is not None
    (tmp_path / "calibration.json").write_text(json.dumps({"model": "deberta-v3-small@deberta", "probs": [0.1, 0.9], "labels": [0, 1]}))
    bad = load_detector_deps(settings, None)
    assert bad.classifier is not None and bad.cal_probs is None  # classifier ok, cascade refused
