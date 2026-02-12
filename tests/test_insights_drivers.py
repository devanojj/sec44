from __future__ import annotations

from datetime import UTC, datetime

from core.engine import build_insight_bundle
from shared.enums import Platform, Severity, Source


def test_driver_attribution_percentages_are_bounded() -> None:
    now = datetime.now(UTC)
    events = [
        {
            "ts": now,
            "source": Source.AUTH.value,
            "severity": Severity.WARN.value,
            "platform": Platform.MACOS.value,
            "title": "failed_login",
            "details_json": {"event_type": "failed_login"},
        },
        {
            "ts": now,
            "source": Source.NETWORK.value,
            "severity": Severity.HIGH.value,
            "platform": Platform.MACOS.value,
            "title": "listener_seen_non_local",
            "details_json": {"ip": "0.0.0.0", "port": 8080, "non_local_bind": True},
        },
        {
            "ts": now,
            "source": Source.PROCESS.value,
            "severity": Severity.INFO.value,
            "platform": Platform.MACOS.value,
            "title": "process_seen",
            "details_json": {"process_name": "a"},
        },
    ]

    bundle = build_insight_bundle(events, now=now)
    total = sum(item.percent for item in bundle.drivers)
    assert 99.0 <= total <= 101.0
    assert all(0.0 <= item.percent <= 100.0 for item in bundle.drivers)
