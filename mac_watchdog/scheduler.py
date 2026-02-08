from __future__ import annotations

import logging
import threading
from datetime import UTC, datetime
from typing import Any

from mac_watchdog.collectors import (
    FileWatchService,
    collect_login_events,
    collect_network_events,
    collect_process_events,
)
from mac_watchdog.config import AppConfig
from mac_watchdog.db import Database
from mac_watchdog.models import EventIn, Severity, Source

logger = logging.getLogger(__name__)


class WatchdogScheduler:
    def __init__(self, config: AppConfig, db: Database, verbose: bool = False) -> None:
        self.config = config
        self.db = db
        self.verbose = verbose
        self._filewatch: FileWatchService | None = None

    def _collect_all(self) -> list[EventIn]:
        events: list[EventIn] = []
        collectors = (
            collect_process_events,
            collect_login_events,
            collect_network_events,
        )
        for collector in collectors:
            try:
                result = collector(self.config, self.db)
                events.extend(result.events)
            except Exception as exc:  # pragma: no cover - defensive top-level guard
                events.append(
                    EventIn(
                        source=Source.SYSTEM,
                        severity=Severity.WARN,
                        title="Collector execution failure",
                        details={"collector": collector.__name__, "error": str(exc)},
                    )
                )

        if self.config.enable_file_watch and self._filewatch is not None:
            try:
                events.extend(self._filewatch.drain_events())
            except Exception as exc:
                events.append(
                    EventIn(
                        source=Source.FILEWATCH,
                        severity=Severity.WARN,
                        title="Filewatch drain error",
                        details={"error": str(exc)},
                    )
                )
        return events

    def run_once(self) -> dict[str, Any]:
        events = self._collect_all()
        inserted = self.db.insert_events(events)
        now = datetime.now(UTC).isoformat()
        self.db.set_app_state("last_run", now)
        self.db.set_app_state("last_run_inserted", str(inserted))

        cycle_counts = {"INFO": 0, "WARN": 0, "HIGH": 0}
        for event in events:
            cycle_counts[event.severity.value] = cycle_counts.get(event.severity.value, 0) + 1
        summary: dict[str, Any] = {
            "timestamp": now,
            "inserted": inserted,
            "counts": cycle_counts,
            "total_events": self.db.total_events(),
        }
        if self.verbose:
            logger.info("collector cycle complete: %s", summary)
        return summary

    def run_daemon(self, stop_event: threading.Event) -> None:
        if self.config.enable_file_watch:
            try:
                self._filewatch = FileWatchService(self.config)
                self._filewatch.start()
            except Exception as exc:
                self.db.insert_event(
                    EventIn(
                        source=Source.FILEWATCH,
                        severity=Severity.WARN,
                        title="Filewatch unavailable",
                        details={"error": str(exc)},
                    )
                )
                self._filewatch = None

        try:
            while not stop_event.is_set():
                self.run_once()
                stop_event.wait(timeout=self.config.interval_seconds)
        finally:
            if self._filewatch is not None:
                self._filewatch.stop()
