from __future__ import annotations

from datetime import UTC, datetime, timedelta

from core.engine import build_insight_bundle
from shared.enums import Platform, Severity, Source


def test_daily_brief_contains_recommendations() -> None:
    now = datetime.now(UTC)
    events = []
    for day in range(3, 0, -1):
        ts = now - timedelta(days=day)
        events.append(
            {
                "ts": ts,
                "source": Source.PROCESS.value,
                "severity": Severity.INFO.value,
                "platform": Platform.MACOS.value,
                "title": "process_seen",
                "details_json": {"process_name": "app", "exe": "/usr/bin/app"},
            }
        )
    for _ in range(3):
        events.append(
            {
                "ts": now,
                "source": Source.AUTH.value,
                "severity": Severity.WARN.value,
                "platform": Platform.MACOS.value,
                "title": "failed_login",
                "details_json": {"event_type": "failed_login", "username": "a"},
            }
        )

    bundle = build_insight_bundle(events, now=now)
    assert bundle.daily_brief.recommended_actions
