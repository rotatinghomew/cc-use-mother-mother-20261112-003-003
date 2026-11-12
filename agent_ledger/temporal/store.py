from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Iterator

from ..errors import ConflictError, NotFoundError, StorageError
from ..models import Decision, DecisionStatus, EventKind, LedgerEvent, Reason
from ..util import canonical_json, format_time, parse_time, sha256_hex, utc_now


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS ledger_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    received_at TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    UNIQUE(kind, entity_id, content_hash)
);
CREATE INDEX IF NOT EXISTS events_kind_time ON events(kind, occurred_at, sequence);
CREATE INDEX IF NOT EXISTS events_entity_time ON events(entity_id, occurred_at, sequence);
CREATE TABLE IF NOT EXISTS declarations (
    declaration_id TEXT PRIMARY KEY,
    developer_id TEXT NOT NULL,
    application_id TEXT NOT NULL,
    agent_identity TEXT NOT NULL,
    action TEXT NOT NULL,
    effective_from TEXT NOT NULL,
    effective_until TEXT,
    priority INTEGER NOT NULL,
    inherited_from TEXT,
    payload_json TEXT NOT NULL,
    source_event_id TEXT NOT NULL UNIQUE,
    content_hash TEXT NOT NULL,
    FOREIGN KEY(source_event_id) REFERENCES events(event_id)
);
CREATE INDEX IF NOT EXISTS declaration_lookup ON declarations(
    developer_id, application_id, agent_identity, effective_from, effective_until
);
CREATE TABLE IF NOT EXISTS requests (
    request_id TEXT PRIMARY KEY,
    requested_at TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    source_event_id TEXT NOT NULL UNIQUE,
    content_hash TEXT NOT NULL,
    FOREIGN KEY(source_event_id) REFERENCES events(event_id)
);
CREATE INDEX IF NOT EXISTS request_time ON requests(requested_at, request_id);
CREATE TABLE IF NOT EXISTS decisions (
    decision_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    status TEXT NOT NULL,
    decided_at TEXT NOT NULL,
    policy_time TEXT NOT NULL,
    reasons_json TEXT NOT NULL,
    matched_json TEXT NOT NULL,
    ledger_revision INTEGER NOT NULL,
    is_current INTEGER NOT NULL DEFAULT 1,
    superseded_by TEXT,
    FOREIGN KEY(request_id) REFERENCES requests(request_id)
);
CREATE INDEX IF NOT EXISTS decision_current ON decisions(request_id, is_current);
CREATE TABLE IF NOT EXISTS recompute_queue (
    request_id TEXT PRIMARY KEY,
    cause_event_id TEXT NOT NULL,
    queued_at TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT
);
CREATE TABLE IF NOT EXISTS audit_records (
    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    detail_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_subject ON audit_records(subject_id, occurred_at);
INSERT OR IGNORE INTO ledger_meta(key, value) VALUES ('revision', '0');
"""


class LedgerStore:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._lock = threading.RLock()
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = NORMAL")
        return connection

    def initialize(self) -> None:
        parent = Path(self.path).parent
        parent.mkdir(parents=True, exist_ok=True)
        with self.session() as connection:
            connection.executescript(SCHEMA)

    @contextmanager
    def session(self) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            connection = self.connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                yield connection
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise
            finally:
                connection.close()

    def append_event(self, event: LedgerEvent, connection: sqlite3.Connection | None = None) -> tuple[LedgerEvent, bool]:
        own = connection is None
        manager = self.transaction() if own else _borrow(connection)
        with manager as db:
            existing = db.execute("SELECT * FROM events WHERE event_id = ?", (event.event_id,)).fetchone()
            if existing is not None:
                stored = self._event(existing)
                if stored.content_hash != event.content_hash:
                    raise ConflictError("event id already exists with different content", details={"event_id": event.event_id})
                return stored, False
            try:
                cursor = db.execute(
                    "INSERT INTO events(event_id, kind, entity_id, occurred_at, received_at, payload_json, content_hash) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        event.event_id,
                        event.kind.value,
                        event.entity_id,
                        format_time(event.occurred_at),
                        format_time(event.received_at),
                        canonical_json(event.payload).decode("utf-8"),
                        event.content_hash,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                duplicate = db.execute(
                    "SELECT * FROM events WHERE kind = ? AND entity_id = ? AND content_hash = ?",
                    (event.kind.value, event.entity_id, event.content_hash),
                ).fetchone()
                if duplicate is not None:
                    return self._event(duplicate), False
                raise StorageError("could not append ledger event", details={"error": str(exc)}) from exc
            self._increment_revision(db)
            stored = LedgerEvent(
                event.event_id, event.kind, event.entity_id, event.occurred_at, event.received_at,
                event.payload, event.content_hash, int(cursor.lastrowid),
            )
            return stored, True

    def save_declaration(self, event: LedgerEvent, connection: sqlite3.Connection) -> bool:
        payload = event.payload
        existing = connection.execute(
            "SELECT content_hash FROM declarations WHERE declaration_id = ?",
            (payload["declaration_id"],),
        ).fetchone()
        if existing is not None:
            if existing["content_hash"] != event.content_hash:
                raise ConflictError("declaration id already exists with different content", details={"declaration_id": payload["declaration_id"]})
            return False
        connection.execute(
            "INSERT INTO declarations(declaration_id, developer_id, application_id, agent_identity, action, effective_from, effective_until, priority, inherited_from, payload_json, source_event_id, content_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                payload["declaration_id"], payload["developer_id"], payload["application_id"],
                payload["agent_identity"], payload["action"], payload["effective_from"],
                payload.get("effective_until"), payload["priority"], payload.get("inherited_from"),
                canonical_json(payload).decode("utf-8"), event.event_id, event.content_hash,
            ),
        )
        return True

    def save_request(self, event: LedgerEvent, connection: sqlite3.Connection) -> bool:
        payload = event.payload
        existing = connection.execute("SELECT content_hash FROM requests WHERE request_id = ?", (payload["request_id"],)).fetchone()
        if existing is not None:
            if existing["content_hash"] != event.content_hash:
                raise ConflictError("request id already exists with different content", details={"request_id": payload["request_id"]})
            return False
        connection.execute(
            "INSERT INTO requests(request_id, requested_at, payload_json, source_event_id, content_hash) VALUES (?, ?, ?, ?, ?)",
            (payload["request_id"], payload["requested_at"], canonical_json(payload).decode("utf-8"), event.event_id, event.content_hash),
        )
        return True

    def get_declaration_payload(self, declaration_id: str) -> dict[str, Any]:
        with self.session() as connection:
            row = connection.execute("SELECT payload_json FROM declarations WHERE declaration_id = ?", (declaration_id,)).fetchone()
        if row is None:
            raise NotFoundError("declaration not found", details={"declaration_id": declaration_id})
        return json.loads(row["payload_json"])

    def get_request_payload(self, request_id: str) -> dict[str, Any]:
        with self.session() as connection:
            row = connection.execute("SELECT payload_json FROM requests WHERE request_id = ?", (request_id,)).fetchone()
        if row is None:
            raise NotFoundError("request not found", details={"request_id": request_id})
        return json.loads(row["payload_json"])

    def declaration_payloads(self) -> list[dict[str, Any]]:
        with self.session() as connection:
            rows = connection.execute("SELECT payload_json FROM declarations ORDER BY effective_from, declaration_id").fetchall()
        return [json.loads(row["payload_json"]) for row in rows]

    def request_payloads(self, *, since: datetime | None = None) -> list[dict[str, Any]]:
        query = "SELECT payload_json FROM requests"
        params: tuple[Any, ...] = ()
        if since is not None:
            query += " WHERE requested_at >= ?"
            params = (format_time(since),)
        query += " ORDER BY requested_at, request_id"
        with self.session() as connection:
            rows = connection.execute(query, params).fetchall()
        return [json.loads(row["payload_json"]) for row in rows]

    def affected_request_ids(self, start: datetime, end: datetime | None, developer_id: str, application_id: str, agent_identity: str) -> list[str]:
        clauses = ["requested_at >= ?"]
        params: list[Any] = [format_time(start)]
        if end is not None:
            clauses.append("requested_at < ?")
            params.append(format_time(end))
        clauses.extend([
            "json_extract(payload_json, '$.developer_id') = ?",
            "json_extract(payload_json, '$.application_id') = ?",
            "json_extract(payload_json, '$.agent_identity') = ?",
        ])
        params.extend([developer_id, application_id, agent_identity])
        query = "SELECT request_id FROM requests WHERE " + " AND ".join(clauses) + " ORDER BY requested_at, request_id"
        with self.session() as connection:
            return [row["request_id"] for row in connection.execute(query, params)]

    def save_decision(self, decision: Decision, connection: sqlite3.Connection | None = None) -> None:
        own = connection is None
        manager = self.transaction() if own else _borrow(connection)
        with manager as db:
            current = db.execute("SELECT decision_id FROM decisions WHERE request_id = ? AND is_current = 1", (decision.request_id,)).fetchone()
            if current is not None and current["decision_id"] == decision.decision_id:
                return
            if current is not None:
                db.execute("UPDATE decisions SET is_current = 0, superseded_by = ? WHERE decision_id = ?", (decision.decision_id, current["decision_id"]))
            db.execute(
                "INSERT OR REPLACE INTO decisions(decision_id, request_id, status, decided_at, policy_time, reasons_json, matched_json, ledger_revision, is_current, superseded_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, NULL)",
                (
                    decision.decision_id, decision.request_id, decision.status.value, format_time(decision.decided_at),
                    format_time(decision.policy_time), canonical_json([reason.as_dict() for reason in decision.reasons]).decode("utf-8"),
                    canonical_json(list(decision.matched_declarations)).decode("utf-8"), decision.ledger_revision,
                ),
            )

    def current_decision(self, request_id: str) -> Decision | None:
        with self.session() as connection:
            row = connection.execute("SELECT * FROM decisions WHERE request_id = ? AND is_current = 1", (request_id,)).fetchone()
        return None if row is None else self._decision(row)

    def decision_history(self, request_id: str) -> list[Decision]:
        with self.session() as connection:
            rows = connection.execute("SELECT * FROM decisions WHERE request_id = ? ORDER BY decided_at, decision_id", (request_id,)).fetchall()
        return [self._decision(row) for row in rows]

    def queue_recompute(self, request_ids: Iterable[str], cause_event_id: str, connection: sqlite3.Connection) -> int:
        count = 0
        now = format_time(utc_now())
        for request_id in request_ids:
            cursor = connection.execute(
                "INSERT INTO recompute_queue(request_id, cause_event_id, queued_at) VALUES (?, ?, ?) ON CONFLICT(request_id) DO UPDATE SET cause_event_id = excluded.cause_event_id, queued_at = excluded.queued_at",
                (request_id, cause_event_id, now),
            )
            count += cursor.rowcount
        return count

    def queued_recomputations(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.session() as connection:
            rows = connection.execute(
                "SELECT request_id, cause_event_id, queued_at, attempts, last_error FROM recompute_queue ORDER BY queued_at, request_id LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def complete_recompute(self, request_id: str) -> None:
        with self.transaction() as connection:
            connection.execute("DELETE FROM recompute_queue WHERE request_id = ?", (request_id,))

    def fail_recompute(self, request_id: str, error: str) -> None:
        with self.transaction() as connection:
            connection.execute(
                "UPDATE recompute_queue SET attempts = attempts + 1, last_error = ? WHERE request_id = ?",
                (error[:1000], request_id),
            )

    def record_audit(self, category: str, subject_id: str, detail: dict[str, Any], connection: sqlite3.Connection | None = None) -> None:
        own = connection is None
        manager = self.transaction() if own else _borrow(connection)
        with manager as db:
            db.execute(
                "INSERT INTO audit_records(category, subject_id, occurred_at, detail_json) VALUES (?, ?, ?, ?)",
                (category, subject_id, format_time(utc_now()), canonical_json(detail).decode("utf-8")),
            )

    def audit_records(self, subject_id: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM audit_records"
        params: tuple[Any, ...] = ()
        if subject_id is not None:
            query += " WHERE subject_id = ?"
            params = (subject_id,)
        query += " ORDER BY audit_id"
        with self.session() as connection:
            rows = connection.execute(query, params).fetchall()
        return [
            {
                "audit_id": row["audit_id"],
                "category": row["category"],
                "subject_id": row["subject_id"],
                "occurred_at": row["occurred_at"],
                "detail": json.loads(row["detail_json"]),
            }
            for row in rows
        ]

    def revision(self, connection: sqlite3.Connection | None = None) -> int:
        if connection is not None:
            row = connection.execute("SELECT value FROM ledger_meta WHERE key = 'revision'").fetchone()
            return int(row["value"])
        with self.session() as db:
            row = db.execute("SELECT value FROM ledger_meta WHERE key = 'revision'").fetchone()
        return int(row["value"])

    def counts(self) -> dict[str, int]:
        tables = ["events", "declarations", "requests", "decisions", "recompute_queue", "audit_records"]
        with self.session() as connection:
            result = {table: int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]) for table in tables}
        result["revision"] = self.revision()
        return result

    @staticmethod
    def event_for(kind: EventKind, entity_id: str, occurred_at: datetime, payload: dict[str, Any], event_id: str, received_at: datetime | None = None) -> LedgerEvent:
        digest = sha256_hex(canonical_json(payload))
        return LedgerEvent(event_id, kind, entity_id, occurred_at, received_at or utc_now(), payload, digest)

    @staticmethod
    def _increment_revision(connection: sqlite3.Connection) -> int:
        connection.execute("UPDATE ledger_meta SET value = CAST(value AS INTEGER) + 1 WHERE key = 'revision'")
        return int(connection.execute("SELECT value FROM ledger_meta WHERE key = 'revision'").fetchone()[0])

    @staticmethod
    def _event(row: sqlite3.Row) -> LedgerEvent:
        return LedgerEvent(
            event_id=row["event_id"], kind=EventKind(row["kind"]), entity_id=row["entity_id"],
            occurred_at=parse_time(row["occurred_at"]), received_at=parse_time(row["received_at"]),
            payload=json.loads(row["payload_json"]), content_hash=row["content_hash"], sequence=row["sequence"],
        )

    @staticmethod
    def _decision(row: sqlite3.Row) -> Decision:
        reasons = tuple(Reason(item["code"], item["message"], item.get("declaration_id"), item.get("details", {})) for item in json.loads(row["reasons_json"]))
        return Decision(
            request_id=row["request_id"], status=DecisionStatus(row["status"]), decided_at=parse_time(row["decided_at"]),
            policy_time=parse_time(row["policy_time"]), reasons=reasons, matched_declarations=tuple(json.loads(row["matched_json"])),
            ledger_revision=row["ledger_revision"], decision_id=row["decision_id"],
        )


@contextmanager
def _borrow(connection: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    yield connection
