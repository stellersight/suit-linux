# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 StellerSight Private Limited
"""Authoritative local state: requests, grants, risk state and the audit chain.

Everything lives in one SQLite database so that a state change and the audit
event describing it commit together or not at all. Every write transaction
starts with BEGIN IMMEDIATE, which takes the database write lock before
reading, so sequence numbers and the chain head cannot race.

The audit chain is locally tamper-evident: each event stores the SHA-256 of
its predecessor and of its own canonical encoding. It is unkeyed. It detects
an edited or removed intermediate record; it does not stop someone with write
access to the database from rebuilding the whole chain, and it cannot show
that the newest records were not truncated. Ship events off the host where
that matters.
"""

import hashlib
import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from suitlinux.clock import wall_iso

DEFAULT_DB = Path("/var/lib/suit/state.db")
GENESIS = "0" * 64

RISK_NORMAL = "NORMAL"
RISK_SUSPENDED = "SUSPENDED"

SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
    id            TEXT PRIMARY KEY,
    uid           INTEGER NOT NULL,
    action        TEXT NOT NULL,
    reason        TEXT NOT NULL,
    duration_s    INTEGER NOT NULL,
    state         TEXT NOT NULL CHECK (state IN ('pending','active','denied','revoked','expired')),
    created_wall  TEXT NOT NULL,
    decided_by    INTEGER,
    decided_wall  TEXT,
    boot_id       TEXT,
    starts_boot   REAL,
    expires_boot  REAL,
    closed_by     INTEGER,
    close_reason  TEXT
);
CREATE INDEX IF NOT EXISTS requests_active ON requests (uid, action, state);
CREATE TABLE IF NOT EXISTS risk_state (
    singleton   INTEGER PRIMARY KEY CHECK (singleton = 1),
    level       TEXT NOT NULL,
    set_by      INTEGER NOT NULL,
    reason      TEXT NOT NULL,
    set_wall    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
    seq        INTEGER PRIMARY KEY,
    record     TEXT NOT NULL,
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL UNIQUE
);
"""


class StoreError(RuntimeError):
    """Raised when an operation is refused. The message is safe to show the caller."""


MAX_REASON = 500


def check_reason(reason: str) -> str:
    """Validates free text that will be stored and later shown on terminals.

    Control characters are refused rather than escaped, so a stored reason can
    never rewrite an approver's terminal when listed.
    """
    if not reason or not reason.strip():
        raise StoreError("a reason is required")
    if len(reason) > MAX_REASON:
        raise StoreError(f"the reason is limited to {MAX_REASON} characters")
    if any(ord(c) < 32 or 127 <= ord(c) < 160 for c in reason):
        raise StoreError("the reason must not contain control characters")
    return reason.strip()


def _canonical(record: Dict[str, Any]) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class Store:
    def __init__(self, path: Path = DEFAULT_DB):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        new = not self.path.exists()
        if new and hasattr(os, "O_NOFOLLOW"):
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        self.db = sqlite3.connect(str(self.path), isolation_level=None, timeout=30)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript(SCHEMA)

    def close(self) -> None:
        self.db.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield self.db
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
        else:
            self.db.execute("COMMIT")

    # -- audit ---------------------------------------------------------------

    def _append_event(self, db: sqlite3.Connection, event: str, actor_uid: int, subject_uid: Optional[int],
                      obj: Optional[str], outcome: str, boot: Optional[str], details: Dict[str, Any]) -> Dict[str, Any]:
        """Appends one suit.audit.v1 event inside the caller's transaction."""
        row = db.execute("SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1").fetchone()
        seq = (row["seq"] + 1) if row else 1
        prev = row["hash"] if row else GENESIS
        record = {
            "schema": "suit.audit.v1",
            "source": "suit-linux",
            "seq": seq,
            "time": wall_iso(),
            "boot_id": boot,
            "event": event,
            "actor": actor_uid,
            "subject": subject_uid,
            "object": obj,
            "outcome": outcome,
            "details": details,
            "prev_hash": prev,
        }
        digest = hashlib.sha256(_canonical(record)).hexdigest()
        db.execute("INSERT INTO audit_events (seq, record, prev_hash, hash) VALUES (?, ?, ?, ?)",
                   (seq, json.dumps(record, sort_keys=True), prev, digest))
        record["hash"] = digest
        return record

    def record_event(self, event: str, actor_uid: int, outcome: str, subject_uid: Optional[int] = None,
                     obj: Optional[str] = None, boot: Optional[str] = None, details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        with self.transaction() as db:
            return self._append_event(db, event, actor_uid, subject_uid, obj, outcome, boot, details or {})

    def verify_chain(self) -> List[str]:
        """Recomputes the chain. Returns a list of problems; empty means consistent."""
        problems: List[str] = []
        expected_prev = GENESIS
        expected_seq = 1
        for row in self.db.execute("SELECT seq, record, prev_hash, hash FROM audit_events ORDER BY seq"):
            if row["seq"] != expected_seq:
                problems.append(f"gap: expected seq {expected_seq}, found {row['seq']}")
                expected_seq = row["seq"]
            record = json.loads(row["record"])
            if record.get("prev_hash") != expected_prev or row["prev_hash"] != expected_prev:
                problems.append(f"seq {row['seq']}: does not link to its predecessor")
            if hashlib.sha256(_canonical(record)).hexdigest() != row["hash"]:
                problems.append(f"seq {row['seq']}: contents do not match their hash")
            expected_prev = row["hash"]
            expected_seq += 1
        return problems

    # -- risk ------------------------------------------------------------------

    def risk_level(self, db: Optional[sqlite3.Connection] = None) -> str:
        row = (db or self.db).execute("SELECT level FROM risk_state WHERE singleton = 1").fetchone()
        return row["level"] if row else RISK_NORMAL

    def set_risk(self, level: str, by_uid: int, reason: str, boot: Optional[str]) -> int:
        """Sets the host risk level. Suspension revokes every active grant in the same transaction.

        Returns the number of grants revoked.
        """
        if level not in (RISK_NORMAL, RISK_SUSPENDED):
            raise StoreError(f"unknown risk level {level}")
        reason = check_reason(reason)
        with self.transaction() as db:
            db.execute(
                "INSERT INTO risk_state (singleton, level, set_by, reason, set_wall) VALUES (1, ?, ?, ?, ?) "
                "ON CONFLICT(singleton) DO UPDATE SET level=excluded.level, set_by=excluded.set_by, "
                "reason=excluded.reason, set_wall=excluded.set_wall",
                (level, by_uid, reason, wall_iso()),
            )
            revoked = 0
            if level == RISK_SUSPENDED:
                ids = [r["id"] for r in db.execute("SELECT id FROM requests WHERE state IN ('active','pending')")]
                for rid in ids:
                    db.execute("UPDATE requests SET state='revoked', closed_by=?, close_reason=? WHERE id=?",
                               (by_uid, f"risk suspension: {reason}", rid))
                revoked = len(ids)
            self._append_event(db, "risk.set", by_uid, None, None, "success", boot,
                               {"level": level, "reason": reason, "requests_closed": revoked})
            return revoked

    # -- requests and grants -----------------------------------------------------

    def create_request(self, uid: int, action: str, reason: str, duration_s: int, boot: Optional[str]) -> str:
        reason = check_reason(reason)
        rid = "r-" + uuid.uuid4().hex[:12]
        with self.transaction() as db:
            if self.risk_level(db) == RISK_SUSPENDED:
                raise StoreError("host is under risk suspension; no requests are accepted")
            db.execute(
                "INSERT INTO requests (id, uid, action, reason, duration_s, state, created_wall) VALUES (?, ?, ?, ?, ?, 'pending', ?)",
                (rid, uid, action, reason, duration_s, wall_iso()),
            )
            self._append_event(db, "request.created", uid, uid, action, "success", boot,
                               {"request": rid, "duration_s": duration_s, "reason": reason})
        return rid

    def get(self, rid: str) -> Optional[sqlite3.Row]:
        return self.db.execute("SELECT * FROM requests WHERE id = ?", (rid,)).fetchone()

    def approve(self, rid: str, approver_uid: int, boot: str, now_boot: float) -> sqlite3.Row:
        with self.transaction() as db:
            req = db.execute("SELECT * FROM requests WHERE id = ?", (rid,)).fetchone()
            if req is None:
                raise StoreError(f"no request {rid}")
            if req["state"] != "pending":
                raise StoreError(f"request {rid} is {req['state']}, not pending")
            if req["uid"] == approver_uid:
                raise StoreError("a request cannot be approved by the person who made it")
            if self.risk_level(db) == RISK_SUSPENDED:
                raise StoreError("host is under risk suspension; no grants can be approved")
            db.execute(
                "UPDATE requests SET state='active', decided_by=?, decided_wall=?, boot_id=?, starts_boot=?, expires_boot=? WHERE id=?",
                (approver_uid, wall_iso(), boot, now_boot, now_boot + req["duration_s"], rid),
            )
            self._append_event(db, "grant.activated", approver_uid, req["uid"], req["action"], "success", boot,
                               {"request": rid, "duration_s": req["duration_s"]})
            return db.execute("SELECT * FROM requests WHERE id = ?", (rid,)).fetchone()

    def deny(self, rid: str, approver_uid: int, reason: str, boot: Optional[str]) -> None:
        reason = check_reason(reason)
        with self.transaction() as db:
            req = db.execute("SELECT * FROM requests WHERE id = ?", (rid,)).fetchone()
            if req is None or req["state"] != "pending":
                raise StoreError(f"request {rid} is not pending")
            db.execute("UPDATE requests SET state='denied', decided_by=?, decided_wall=?, close_reason=? WHERE id=?",
                       (approver_uid, wall_iso(), reason, rid))
            self._append_event(db, "request.denied", approver_uid, req["uid"], req["action"], "success", boot,
                               {"request": rid, "reason": reason})

    def revoke(self, rid: str, by_uid: int, reason: str, boot: Optional[str]) -> None:
        reason = check_reason(reason)
        with self.transaction() as db:
            req = db.execute("SELECT * FROM requests WHERE id = ?", (rid,)).fetchone()
            if req is None or req["state"] not in ("active", "pending"):
                raise StoreError(f"request {rid} is not active or pending")
            db.execute("UPDATE requests SET state='revoked', closed_by=?, close_reason=? WHERE id=?", (by_uid, reason, rid))
            self._append_event(db, "grant.revoked", by_uid, req["uid"], req["action"], "success", boot,
                               {"request": rid, "reason": reason})

    def authorize(self, uid: int, action: str, boot: str, now_boot: float) -> Optional[sqlite3.Row]:
        """Returns the grant that authorises uid to run action now, or None.

        Grants from another boot, or past their deadline, are closed as
        expired in the same transaction, so state never claims an active grant
        that can no longer be used.
        """
        with self.transaction() as db:
            if self.risk_level(db) == RISK_SUSPENDED:
                return None
            for req in db.execute("SELECT * FROM requests WHERE uid=? AND action=? AND state='active'", (uid, action)).fetchall():
                if req["boot_id"] != boot or now_boot >= req["expires_boot"]:
                    why = "reboot" if req["boot_id"] != boot else "deadline"
                    db.execute("UPDATE requests SET state='expired', close_reason=? WHERE id=?", (why, req["id"]))
                    self._append_event(db, "grant.expired", 0, uid, action, "success", boot, {"request": req["id"], "cause": why})
                    continue
                return req
            return None

    def list_requests(self, states: Optional[List[str]] = None) -> List[sqlite3.Row]:
        if states:
            marks = ",".join("?" * len(states))
            return self.db.execute(f"SELECT * FROM requests WHERE state IN ({marks}) ORDER BY created_wall", states).fetchall()
        return self.db.execute("SELECT * FROM requests ORDER BY created_wall").fetchall()
