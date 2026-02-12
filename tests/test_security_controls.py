from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from mac_watchdog.config import AppConfig
from mac_watchdog.db import Database
from mac_watchdog.models import EventIn, Severity, Source
from mac_watchdog.web.app import create_app


def test_templates_escape_untrusted_html(tmp_path: Path) -> None:
    db = Database(tmp_path / "escape.db")
    cfg = AppConfig()
    try:
        db.insert_event(
            EventIn(
                source=Source.PROCESS,
                severity=Severity.WARN,
                title="<script>alert(1)</script>",
                details={"sample": "<script>alert(1)</script>"},
            )
        )
        client = TestClient(create_app(cfg, db))
        response = client.get("/events")
        assert response.status_code == 200
        assert "<script>alert(1)</script>" not in response.text
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in response.text
    finally:
        db.close()


def test_sql_parameterized_event_filters(tmp_path: Path) -> None:
    db = Database(tmp_path / "sql.db")
    try:
        db.insert_event(
            EventIn(
                source=Source.PROCESS,
                severity=Severity.INFO,
                title="Normal process event",
                details={"ok": True},
            )
        )
        malicious_source = "process' OR 1=1 --"
        rows = db.get_events(source=malicious_source)
        assert rows == []
        assert db.total_events() == 1
    finally:
        db.close()
