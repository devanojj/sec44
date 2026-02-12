from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from mac_watchdog.db import Database
from mac_watchdog.insights.schemas import (
    InsightConfidence,
    InsightCreate,
    InsightSeverity,
    InsightSource,
    InsightType,
)
from mac_watchdog.services.insight_service import InsightService


def test_repeated_alerts_collapse_by_fingerprint(tmp_path: Path) -> None:
    db = Database(tmp_path / "insights.db")
    service = InsightService(db=db, dedup_window_minutes=30)
    ts = datetime.now(UTC).isoformat()

    insight = InsightCreate(
        ts=ts,
        insight_type=InsightType.CHANGE,
        source=InsightSource.NETWORK,
        severity=InsightSeverity.HIGH,
        confidence=InsightConfidence.HIGH,
        title="New risk introduced: New external listener on all interfaces",
        explanation="Rule text",
        evidence={"ip": "0.0.0.0", "port": 6666, "process_name": "demo"},
        action_text="Close the unexpected listener.",
    )

    try:
        first = service.record_insight(insight)
        second = service.record_insight(insight)
        listed = service.list_insights(page=1, page_size=20)

        assert first.fingerprint == second.fingerprint
        assert len(listed) == 1
        assert listed[0].count == 2
    finally:
        db.close()
