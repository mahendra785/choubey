"""Seed script: creates the first admin from ADMIN_EMAIL / ADMIN_PASSWORD and the target-app rows.

Run:  python -m app.db.seed      (idempotent)
"""
from __future__ import annotations

import sys

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import audit
from app.core.config import get_settings
from app.core.security import hash_password
from app.db.models import Role, TargetApp, User
from app.db.session import SessionLocal

TARGETS = [
    ("rag_bot", "rag", "Company knowledge-base Q&A over local documents. Canary in system prompt."),
    ("email_agent", "agent", "Summarises an inbox and can call mock tools. Two tools are forbidden."),
    ("support_bot", "chat", "Customer-support bot holding a confidential discount-code canary."),
]


def seed(db: Session, email: str, password: str) -> str:
    for name, kind, desc in TARGETS:
        if db.scalar(select(TargetApp).where(TargetApp.name == name)) is None:
            db.add(TargetApp(name=name, kind=kind, description=desc))
    if db.scalar(select(User).where(User.email == email.lower())):
        db.commit()
        return "admin already exists"
    if len(password) < 12:
        raise ValueError("ADMIN_PASSWORD must be at least 12 characters")
    admin = User(email=email.lower(), password_hash=hash_password(password), role=Role.admin.value)
    db.add(admin)
    db.flush()
    audit.append_event(db, "admin_seeded", admin.id, {"email": admin.email})
    db.commit()
    return "admin created"


def main() -> int:
    s = get_settings()
    if not s.admin_email or not s.admin_password:
        print("ADMIN_EMAIL and ADMIN_PASSWORD must be set", file=sys.stderr)
        return 1
    with SessionLocal() as db:
        print(seed(db, s.admin_email, s.admin_password))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
