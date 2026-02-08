from __future__ import annotations

import json
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mac_watchdog.config import secure_path
from mac_watchdog.models import EventIn
from mac_watchdog.sanitizer import safe_json_dumps, sanitize_text


class Database:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path.expanduser().resolve(strict=False)
        if self.db_path.exists() and self.db_path.is_symlink():
            raise ValueError(f"refusing symlinked database file: {self.db_path}")
        if self.db_path.parent.exists() and self.db_path.parent.is_symlink():
            raise ValueError(f"refusing symlinked database directory: {self.db_path.parent}")
        self.db_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        secure_path(self.db_path.parent, 0o700)

        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._init_schema()
        secure_path(self.db_path, 0o600)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _init_schema(self) -> None:
        with self._lock, self._conn:
            self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute("PRAGMA synchronous=NORMAL;")
            self._conn.execute("PRAGMA foreign_keys=ON;")
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events(
                  id INTEGER PRIMARY KEY,
                  ts TEXT NOT NULL,
                  source TEXT NOT NULL,
                  severity TEXT NOT NULL,
                  title TEXT NOT NULL,
                  details_json TEXT NOT NULL
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS process_seen(
                  process_key TEXT PRIMARY KEY,
                  first_seen TEXT NOT NULL,
                  last_seen TEXT NOT NULL
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS latest_snapshots(
                  key TEXT PRIMARY KEY,
                  ts TEXT NOT NULL,
                  blob_json TEXT NOT NULL
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS app_state(
                  key TEXT PRIMARY KEY,
                  value TEXT NOT NULL
                )
                """
            )
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_events_source ON events(source)")
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)")

    def insert_event(self, event: EventIn) -> None:
        self.insert_events([event])

    def insert_events(self, events: list[EventIn]) -> int:
        if not events:
            return 0
        rows: list[tuple[str, str, str, str, str]] = []
        for event in events:
            rows.append(
                (
                    sanitize_text(event.ts),
                    sanitize_text(event.source.value),
                    sanitize_text(event.severity.value),
                    sanitize_text(event.title),
                    safe_json_dumps(event.details),
                )
            )
        with self._lock, self._conn:
            self._conn.executemany(
                "INSERT INTO events(ts, source, severity, title, details_json) VALUES(?,?,?,?,?)", rows
            )
        return len(rows)

    def touch_process_seen(self, process_key: str, now_ts: str | None = None) -> bool:
        ts = now_ts or datetime.now(UTC).isoformat()
        key = sanitize_text(process_key)
        with self._lock, self._conn:
            existing = self._conn.execute(
                "SELECT 1 FROM process_seen WHERE process_key = ?", (key,)
            ).fetchone()
            if existing is None:
                self._conn.execute(
                    "INSERT INTO process_seen(process_key, first_seen, last_seen) VALUES(?,?,?)",
                    (key, ts, ts),
                )
                return True
            self._conn.execute(
                "UPDATE process_seen SET last_seen = ? WHERE process_key = ?",
                (ts, key),
            )
            return False

    def set_latest_snapshot(self, key: str, blob: Any, ts: str | None = None) -> None:
        at = ts or datetime.now(UTC).isoformat()
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO latest_snapshots(key, ts, blob_json)
                VALUES(?,?,?)
                ON CONFLICT(key)
                DO UPDATE SET ts = excluded.ts, blob_json = excluded.blob_json
                """,
                (sanitize_text(key), sanitize_text(at), safe_json_dumps(blob)),
            )

    def get_latest_snapshot(self, key: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT ts, blob_json FROM latest_snapshots WHERE key = ?", (sanitize_text(key),)
            ).fetchone()
        if row is None:
            return None
        try:
            blob = json.loads(row["blob_json"])
        except json.JSONDecodeError:
            blob = {}
        return {"ts": row["ts"], "blob": blob}

    def set_app_state(self, key: str, value: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO app_state(key, value)
                VALUES(?,?)
                ON CONFLICT(key)
                DO UPDATE SET value = excluded.value
                """,
                (sanitize_text(key), sanitize_text(value)),
            )

    def get_app_state(self, key: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM app_state WHERE key = ?", (sanitize_text(key),)
            ).fetchone()
        return None if row is None else str(row["value"])

    def get_events(
        self,
        severity: str | None = None,
        source: str | None = None,
        start_ts: str | None = None,
        end_ts: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if source:
            clauses.append("source = ?")
            params.append(source)
        if start_ts:
            clauses.append("ts >= ?")
            params.append(start_ts)
        if end_ts:
            clauses.append("ts <= ?")
            params.append(end_ts)

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        page_safe = max(page, 1)
        page_size_safe = min(max(page_size, 1), 200)
        offset = (page_safe - 1) * page_size_safe

        query = (
            "SELECT id, ts, source, severity, title, details_json "
            f"FROM events {where_sql} ORDER BY ts DESC LIMIT ? OFFSET ?"
        )
        params.extend([page_size_safe, offset])

        with self._lock:
            rows = self._conn.execute(query, tuple(params)).fetchall()

        output: list[dict[str, Any]] = []
        for row in rows:
            details: Any
            try:
                details = json.loads(row["details_json"])
            except json.JSONDecodeError:
                details = {}
            output.append(
                {
                    "id": row["id"],
                    "ts": row["ts"],
                    "source": row["source"],
                    "severity": row["severity"],
                    "title": row["title"],
                    "details": details,
                }
            )
        return output

    def count_events_by_severity(self, since_ts: str | None = None) -> dict[str, int]:
        params: tuple[Any, ...]
        sql = "SELECT severity, COUNT(*) AS c FROM events"
        if since_ts:
            sql += " WHERE ts >= ?"
            params = (since_ts,)
        else:
            params = ()
        sql += " GROUP BY severity"

        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        result = {"INFO": 0, "WARN": 0, "HIGH": 0}
        for row in rows:
            result[str(row["severity"])] = int(row["c"])
        return result

    def total_events(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()
        return 0 if row is None else int(row["c"])

    def latest_events(self, limit: int = 20) -> list[dict[str, Any]]:
        return self.get_events(page=1, page_size=min(max(limit, 1), 100))
