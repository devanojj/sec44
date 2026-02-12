from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from mac_watchdog.config import AppConfig
from mac_watchdog.db import Database
from mac_watchdog.insights import InsightEngine


def test_insight_engine_handles_missing_data_without_crashing(tmp_path: Path) -> None:
    db = Database(tmp_path / "engine.db")
    engine = InsightEngine(config=AppConfig(), db=db)
    try:
        result = engine.generate_cycle(now=datetime.now(UTC))
        assert result.generated_insights >= 1
        metric = engine.metrics_service.get_metrics(result.date)
        assert metric is not None
    finally:
        db.close()


def test_insight_engine_handles_bad_event_json(tmp_path: Path) -> None:
    db = Database(tmp_path / "engine_bad_json.db")
    engine = InsightEngine(config=AppConfig(), db=db)
    now = datetime.now(UTC)
    try:
        db.execute(
            "INSERT INTO events(ts, source, severity, title, details_json) VALUES(?,?,?,?,?)",
            (now.isoformat(), "network", "HIGH", "Malformed details", "{bad-json"),
        )
        result = engine.generate_cycle(now=now)
        assert result.risk_score >= 0
    finally:
        db.close()
