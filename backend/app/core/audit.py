"""Tamper-evident audit log: a hash chain stored in the database.

Each row stores ``prev_hash`` (the hash of the previous row) and
``hash = SHA256(prev_hash + canonical_record)``. Changing any past row changes its hash, which no
longer matches the ``prev_hash`` stored in the next row, so ``verify_chain`` finds the break.

Honest limitations (documented in THREAT_MODEL.md):
* An attacker with DB write access who recomputes *every* later hash can forge a consistent chain.
  Mitigation in production: periodically anchor the head hash somewhere the DB admin cannot write.
* Deleting the *latest* rows is not detectable from the chain alone, for the same reason.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import AuditLog, new_id

GENESIS_HASH = "0" * 64


def _canonical(event_id: str, ts: str, actor_id: str | None, action: str, detail: str) -> str:
    # Fixed key order + compact separators => the same record always serialises to the same bytes.
    return json.dumps(
        {"event_id": event_id, "ts": ts, "actor_id": actor_id, "action": action, "detail": detail},
        sort_keys=True,
        separators=(",", ":"),
    )


def compute_hash(prev_hash: str, event_id: str, ts: str, actor_id: str | None, action: str, detail: str) -> str:
    record = _canonical(event_id, ts, actor_id, action, detail)
    return hashlib.sha256((prev_hash + record).encode()).hexdigest()


def append_event(db: Session, action: str, actor_id: str | None = None, detail: dict[str, Any] | None = None) -> AuditLog:
    """Append one event to the chain. The caller commits (so the event shares the request transaction).

    ``detail`` must never contain passwords/tokens; callers pass only identifiers and outcomes.
    """
    # Lock the chain tip so two concurrent writers cannot both extend the same predecessor (no-op on SQLite).
    tip = db.execute(select(AuditLog).order_by(AuditLog.seq.desc()).limit(1).with_for_update()).scalar_one_or_none()
    prev_hash = tip.hash if tip else GENESIS_HASH
    event_id = new_id()
    ts = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    detail_json = json.dumps(detail or {}, sort_keys=True, separators=(",", ":"), default=str)
    row = AuditLog(
        event_id=event_id,
        ts=ts,
        actor_id=actor_id,
        action=action,
        detail=detail_json,
        prev_hash=prev_hash,
        hash=compute_hash(prev_hash, event_id, ts, actor_id, action, detail_json),
    )
    db.add(row)
    db.flush()
    return row


@dataclass
class VerifyResult:
    valid: bool
    checked: int
    broken_at_seq: int | None = None
    reason: str | None = None


def verify_chain(db: Session) -> VerifyResult:
    """Recompute every hash from genesis and compare with what is stored."""
    expected_prev = GENESIS_HASH
    checked = 0
    for row in db.execute(select(AuditLog).order_by(AuditLog.seq.asc())).scalars():
        if row.prev_hash != expected_prev:
            return VerifyResult(False, checked, row.seq, "prev_hash does not match previous record (row removed or reordered)")
        recomputed = compute_hash(row.prev_hash, row.event_id, row.ts, row.actor_id, row.action, row.detail)
        if recomputed != row.hash:
            return VerifyResult(False, checked, row.seq, "record content does not match its hash (row modified)")
        expected_prev = row.hash
        checked += 1
    return VerifyResult(True, checked)
