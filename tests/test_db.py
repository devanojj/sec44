from __future__ import annotations

from pathlib import Path

from mac_watchdog.db import Database


def test_db_schema_and_indexes(tmp_path: Path) -> None:
    db_path = tmp_path / "mac_watchdog.db"
    db = Database(db_path)
    try:
        cursor = db._conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}
        assert {"events", "process_seen", "latest_snapshots", "app_state"}.issubset(tables)

        cursor = db._conn.execute("SELECT name FROM sqlite_master WHERE type='index'")
        indexes = {row[0] for row in cursor.fetchall()}
        assert "idx_events_ts" in indexes
        assert "idx_events_source" in indexes
        assert "idx_events_severity" in indexes

        mode = db._conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert str(mode).lower() == "wal"
    finally:
        db.close()
