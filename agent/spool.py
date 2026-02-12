from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from shared.schemas import EventEnvelope


@dataclass(slots=True)
class SpoolBatch:
    batch_id: int
    events: list[EventEnvelope]
    retry_count: int


class Spooler:
    def __init__(self, db_path: Path, max_batches: int = 1000) -> None:
        self.db_path = db_path.expanduser().resolve(strict=False)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.max_batches = max_batches
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _init_schema(self) -> None:
        with self._lock, self._conn:
            self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS spool_batches(
                    id INTEGER PRIMARY KEY,
                    events_json TEXT NOT NULL,
                    event_count INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    retry_count INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at TEXT NOT NULL
                )
                """
            )
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_spool_due ON spool_batches(next_attempt_at)")

    def enqueue(self, events: list[EventEnvelope]) -> int:
        if not events:
            return 0
        payload = [event.model_dump(mode="json") for event in events]
        now = datetime.now(UTC).isoformat()
        with self._lock, self._conn:
            cursor = self._conn.execute(
                "INSERT INTO spool_batches(events_json, event_count, created_at, retry_count, next_attempt_at) VALUES(?,?,?,?,?)",
                (json.dumps(payload, ensure_ascii=True, separators=(",", ":")), len(payload), now, 0, now),
            )
            batch_id = int(cursor.lastrowid)
        self.enforce_limit()
        return batch_id

    def due_batches(self, limit: int = 20) -> list[SpoolBatch]:
        now = datetime.now(UTC).isoformat()
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, events_json, retry_count FROM spool_batches WHERE next_attempt_at <= ? ORDER BY id ASC LIMIT ?",
                (now, limit),
            ).fetchall()

        output: list[SpoolBatch] = []
        for row in rows:
            try:
                items = json.loads(str(row["events_json"]))
            except json.JSONDecodeError:
                items = []
            events: list[EventEnvelope] = []
            if isinstance(items, list):
                for item in items:
                    try:
                        events.append(EventEnvelope.model_validate(item))
                    except Exception:
                        continue
            output.append(SpoolBatch(batch_id=int(row["id"]), events=events, retry_count=int(row["retry_count"])))
        return output

    def mark_sent(self, batch_id: int) -> None:
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM spool_batches WHERE id = ?", (batch_id,))

    def mark_failed(self, batch_id: int, retry_count: int) -> None:
        backoff_seconds = min(300, max(2, 2**retry_count))
        retry_at = (datetime.now(UTC) + timedelta(seconds=backoff_seconds)).isoformat()
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE spool_batches SET retry_count = retry_count + 1, next_attempt_at = ? WHERE id = ?",
                (retry_at, batch_id),
            )

    def enforce_limit(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(1) AS c FROM spool_batches").fetchone()
            total = int(row["c"]) if row else 0
            if total <= self.max_batches:
                return 0
            drop_count = total - self.max_batches
            with self._conn:
                self._conn.execute(
                    "DELETE FROM spool_batches WHERE id IN (SELECT id FROM spool_batches ORDER BY created_at ASC LIMIT ?)",
                    (drop_count,),
                )
            return drop_count

    def count(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(1) AS c FROM spool_batches").fetchone()
        return int(row["c"]) if row else 0
