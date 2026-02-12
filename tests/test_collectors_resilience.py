from __future__ import annotations

from agent.platforms.windows.auth import WindowsAuthCollector


def test_windows_auth_collector_graceful_without_eventlog() -> None:
    collector = WindowsAuthCollector(max_events=5)
    events = collector.collect()
    assert events
    assert events[0].title in {"windows_eventlog_unavailable", "windows_eventlog_access_denied", "windows_failed_login", "windows_successful_login"}
