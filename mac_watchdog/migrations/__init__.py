from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

MIGRATION_DIR = Path(__file__).resolve().parent
MIGRATION_FILES: list[tuple[int, str]] = [
    (1, "0001_daily_metrics_insights.sql"),
]


def ensure_migration_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations(
          version INTEGER PRIMARY KEY,
          applied_at TEXT NOT NULL
        )
        """
    )


def get_applied_versions(conn: sqlite3.Connection) -> set[int]:
    rows = conn.execute("SELECT version FROM schema_migrations").fetchall()
    return {int(row[0]) for row in rows}


def apply_migrations(conn: sqlite3.Connection) -> int:
    ensure_migration_table(conn)
    applied = get_applied_versions(conn)
    applied_count = 0

    for version, filename in MIGRATION_FILES:
        if version in applied:
            continue
        sql_path = MIGRATION_DIR / filename
        sql = sql_path.read_text(encoding="utf-8")
        conn.executescript(sql)
        conn.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)",
            (version, datetime.now(UTC).isoformat()),
        )
        applied_count += 1

    return applied_count


def current_version(conn: sqlite3.Connection) -> int:
    ensure_migration_table(conn)
    row = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
    if row is None or row[0] is None:
        return 0
    return int(row[0])
