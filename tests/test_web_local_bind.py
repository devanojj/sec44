from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from mac_watchdog.config import AppConfig
from mac_watchdog.db import Database
from mac_watchdog.main import build_parser
from mac_watchdog.web.app import create_app


def test_web_routes_and_docs_disabled(tmp_path: Path) -> None:
    cfg = AppConfig()
    db = Database(tmp_path / "web.db")
    try:
        app = create_app(cfg, db)
        client = TestClient(app)

        assert client.get("/").status_code == 200
        assert client.get("/overview").status_code == 200
        assert client.get("/insights").status_code == 200
        assert client.get("/events").status_code == 200
        assert client.get("/listeners").status_code == 200
        assert client.get("/settings").status_code == 200
        assert client.get("/docs").status_code == 404
        assert client.get("/redoc").status_code == 404

        headers = client.get("/overview").headers
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["x-frame-options"] == "DENY"
        assert headers["referrer-policy"] == "no-referrer"
        assert "content-security-policy" in headers
    finally:
        db.close()


def test_serve_command_default_host_localhost() -> None:
    parser = build_parser()
    args = parser.parse_args(["serve"])
    assert args.host == "127.0.0.1"
