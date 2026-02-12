from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

from core.dedup import suppress_repeated
from core.models import Insight
from shared.enums import Severity, Source


def test_dedup_suppresses_recent_identical_insights() -> None:
    now = datetime.now(UTC)
    insight = Insight(
        ts=now,
        day=date.today(),
        insight_type="anomaly",
        source=Source.AUTH,
        severity=Severity.WARN,
        title="failed_logins high",
        explanation="test",
        evidence={"metric": "failed_logins"},
        fingerprint="abc123",
    )

    accepted, suppressed = suppress_repeated(
        [insight],
        recent_last_seen={"abc123": now - timedelta(minutes=10)},
        now=now,
        window_minutes=30,
    )
    assert accepted == []
    assert suppressed == ["abc123"]
