"""Shared fixtures: in-memory SQLite DB, TestClient over HTTPS (Secure cookies), user helpers."""
from __future__ import annotations

import os

# Must be set BEFORE app modules import (settings are read once at import time).
os.environ.setdefault("JWT_SECRET", "test-secret-" + "x" * 40)
os.environ.setdefault("RATE_LIMIT_ENABLED", "false")
os.environ.setdefault("DATABASE_URL", "sqlite://")
os.environ.setdefault("FRONTEND_ORIGIN", "http://localhost:3000")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.core.rate_limit import limiter  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.db.models import Base, Role, User  # noqa: E402
from app.db.session import get_db  # noqa: E402
from app.main import app  # noqa: E402

PASSWORD = "Correct-Horse-Battery-9"


@pytest.fixture()
def engine():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture()
def SessionTest(engine):
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


@pytest.fixture()
def db(SessionTest):
    with SessionTest() as session:
        yield session


@pytest.fixture()
def client(SessionTest):
    def _get_db():
        with SessionTest() as session:
            yield session

    app.dependency_overrides[get_db] = _get_db
    limiter.reset()
    # https base_url so the browser-like cookie jar will send our Secure cookies back.
    with TestClient(app, base_url="https://testserver") as c:
        yield c
    app.dependency_overrides.clear()


def make_user(db, email: str, role: Role = Role.viewer, password: str = PASSWORD) -> User:
    user = User(email=email, password_hash=hash_password(password), role=role.value)
    db.add(user)
    db.commit()
    return user


class Session:
    """A logged-in API session that attaches the CSRF header automatically."""

    def __init__(self, client: TestClient, csrf: str):
        self.c = client
        self.h = {"X-CSRF-Token": csrf}

    def get(self, *a, **k):
        return self.c.get(*a, **k)

    def post(self, *a, **k):
        return self.c.post(*a, headers=self.h, **k)

    def patch(self, *a, **k):
        return self.c.patch(*a, headers=self.h, **k)

    def delete(self, *a, **k):
        return self.c.delete(*a, headers=self.h, **k)


def login(client: TestClient, email: str, password: str = PASSWORD) -> Session:
    r = client.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return Session(client, r.json()["csrf_token"])


@pytest.fixture()
def admin_user(db):
    return make_user(db, "admin@example.com", Role.admin)


@pytest.fixture()
def researcher_user(db):
    return make_user(db, "researcher@example.com", Role.researcher)


@pytest.fixture()
def viewer_user(db):
    return make_user(db, "viewer@example.com", Role.viewer)
