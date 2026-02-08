from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from mac_watchdog.collectors.logins import collect_login_events
from mac_watchdog.collectors.network import collect_network_events
from mac_watchdog.collectors.processes import collect_process_events
from mac_watchdog.config import AppConfig
from mac_watchdog.db import Database


@pytest.fixture()
def config() -> AppConfig:
    return AppConfig()


@pytest.fixture()
def db(tmp_path: Path) -> Database:
    instance = Database(tmp_path / "watchdog.db")
    try:
        yield instance
    finally:
        instance.close()


def test_process_collector_handles_psutil_error(monkeypatch: pytest.MonkeyPatch, config: AppConfig, db: Database) -> None:
    def _raise(*args: object, **kwargs: object) -> object:
        raise RuntimeError("boom")

    monkeypatch.setattr("mac_watchdog.collectors.processes.psutil.process_iter", _raise)
    result = collect_process_events(config, db)
    assert any(evt.severity.value == "WARN" for evt in result.events)


def test_login_collector_handles_timeout(monkeypatch: pytest.MonkeyPatch, config: AppConfig, db: Database) -> None:
    def _raise(*args: object, **kwargs: object) -> object:
        raise subprocess.TimeoutExpired(cmd=["/usr/bin/log"], timeout=8)

    monkeypatch.setattr("mac_watchdog.collectors.logins.subprocess.run", _raise)
    result = collect_login_events(config, db)
    assert any("timeout" in evt.title.lower() for evt in result.events)


def test_network_collector_handles_error(monkeypatch: pytest.MonkeyPatch, config: AppConfig, db: Database) -> None:
    def _raise(*args: object, **kwargs: object) -> object:
        raise RuntimeError("denied")

    monkeypatch.setattr("mac_watchdog.collectors.network.psutil.net_connections", _raise)
    result = collect_network_events(config, db)
    assert any(evt.severity.value == "WARN" for evt in result.events)
