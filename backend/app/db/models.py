"""ORM models (SQLAlchemy 2.0 typed style).

Portable column types only (String/Integer/JSON/DateTime) so the same models run on
PostgreSQL in production and SQLite in unit tests.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def as_utc(dt: datetime) -> datetime:
    """SQLite returns naive datetimes; PostgreSQL returns aware ones. Normalise to aware UTC."""
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def new_id() -> str:
    return uuid.uuid4().hex


class Base(DeclarativeBase):
    """Common base class for all ORM models."""


class Role(str, enum.Enum):
    """RBAC roles. Stored as a string column on User (a separate table adds nothing for 3 fixed roles)."""

    admin = "admin"
    researcher = "researcher"
    viewer = "viewer"


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default=Role.viewer.value)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RefreshToken(Base):
    """Server-side record of an issued refresh token. Only the SHA-256 hash is stored."""

    __tablename__ = "refresh_tokens"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    family_id: Mapped[str] = mapped_column(String(32), index=True)  # all rotations of one login share a family
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditLog(Base):
    """Append-only, hash-chained security log. See app/core/audit.py."""

    __tablename__ = "audit_log"

    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(32), unique=True, default=new_id)
    ts: Mapped[str] = mapped_column(String(40))  # ISO-8601 string: hashed byte-for-byte, no tz/format drift
    actor_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    action: Mapped[str] = mapped_column(String(64))
    detail: Mapped[str] = mapped_column(Text)  # canonical JSON string
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


class TargetApp(Base):
    __tablename__ = "target_apps"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    kind: Mapped[str] = mapped_column(String(32))
    description: Mapped[str] = mapped_column(Text, default="")


class AttackPayload(Base):
    __tablename__ = "attack_payloads"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    category: Mapped[str] = mapped_column(String(48), index=True)
    technique: Mapped[str] = mapped_column(String(96))
    vector: Mapped[str] = mapped_column(String(16))
    text: Mapped[str] = mapped_column(Text)
    multi_turn: Mapped[Any] = mapped_column(JSON, nullable=True)
    target_compat: Mapped[Any] = mapped_column(JSON, default=list)
    parent_id: Mapped[str | None] = mapped_column(String(64), nullable=True)  # lineage for mutated variants
    mutation: Mapped[str | None] = mapped_column(String(64), nullable=True)


class DefenseConfig(Base):
    __tablename__ = "defense_configs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(80), index=True)
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    config: Mapped[Any] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Experiment(Base):
    __tablename__ = "experiments"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    kind: Mapped[str] = mapped_column(String(24), default="end_to_end")  # end_to_end | conformal_sweep
    status: Mapped[str] = mapped_column(String(16), default="queued")  # queued|running|done|failed
    shared: Mapped[bool] = mapped_column(Boolean, default=False)  # viewers may read shared experiments only
    config: Mapped[Any] = mapped_column(JSON)
    seed: Mapped[int] = mapped_column(Integer, default=0)
    model: Mapped[str] = mapped_column(String(120), default="")
    total: Mapped[int] = mapped_column(Integer, default=0)
    completed: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    summary: Mapped[Any] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    results: Mapped[list["ExperimentResult"]] = relationship(back_populates="experiment", cascade="all, delete-orphan")


class ExperimentResult(Base):
    __tablename__ = "experiment_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    experiment_id: Mapped[str] = mapped_column(ForeignKey("experiments.id"), index=True)
    experiment: Mapped[Experiment] = relationship(back_populates="results")
    kind: Mapped[str] = mapped_column(String(8))  # attack | benign
    target: Mapped[str] = mapped_column(String(48), index=True)
    defense: Mapped[str] = mapped_column(String(64), index=True)
    payload_id: Mapped[str] = mapped_column(String(80))
    category: Mapped[str] = mapped_column(String(48), default="")
    vector: Mapped[str] = mapped_column(String(16), default="")
    ood: Mapped[bool] = mapped_column(Boolean, default=False)
    success: Mapped[bool] = mapped_column(Boolean, default=False)  # canary leaked or forbidden tool invoked
    canary_form: Mapped[str | None] = mapped_column(String(24), nullable=True)
    forbidden_tool: Mapped[bool] = mapped_column(Boolean, default=False)
    blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    escalated: Mapped[bool] = mapped_column(Boolean, default=False)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    defense_latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    llm_calls: Mapped[int] = mapped_column(Integer, default=0)
    response_text: Mapped[str] = mapped_column(Text, default="")
    decisions: Mapped[Any] = mapped_column(JSON, nullable=True)


class ToolCall(Base):
    """A call to a MOCK tool. Pure log row: the tool itself never does anything real."""

    __tablename__ = "tool_calls"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    experiment_id: Mapped[str | None] = mapped_column(ForeignKey("experiments.id"), nullable=True, index=True)
    result_id: Mapped[int | None] = mapped_column(ForeignKey("experiment_results.id"), nullable=True)
    target: Mapped[str] = mapped_column(String(48))
    tool: Mapped[str] = mapped_column(String(48))
    arguments: Mapped[Any] = mapped_column(JSON)
    forbidden: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
