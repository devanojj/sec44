from __future__ import annotations

from datetime import UTC, datetime, timedelta

from core.engine import build_insight_bundle
from shared.enums import Platform, Severity, Source


def _event(ts: datetime, severity: Severity, title: str) -> dict[str, object]:
    return {
        "ts": ts,
        "source": Source.AUTH.value,
        "severity": severity.value,
        "platform": Platform.MACOS.value,
        "title": title,
        "details_json": {"event_type": "failed_login", "username": "alice"},
    }


def test_baseline_classifies_anomalous_failed_logins() -> None:
    now = datetime.now(UTC).replace(hour=12, minute=0, second=0, microsecond=0)
    events: list[dict[str, object]] = []

    for days_ago in range(14, 0, -1):
        day = now - timedelta(days=days_ago)
        events.append(_event(day, Severity.WARN, "failed_login"))

    for _ in range(8):
        events.append(_event(now, Severity.WARN, "failed_login"))

    bundle = build_insight_bundle(events, now=now)
    metric = bundle.baseline["failed_logins"]

    assert metric.classification.value == "anomalous"
    assert metric.ratio >= 3
    assert any(insight.insight_type == "anomaly" for insight in bundle.insights)
