from __future__ import annotations

import logging
import threading

from server.db import ServerDatabase
from server.insights import ComputeTimeoutError, compute_device_insights

logger = logging.getLogger("endpoint_server.scheduler")


class InsightScheduler:
    def __init__(self, db: ServerDatabase, interval_seconds: int, max_compute_seconds: int) -> None:
        self.db = db
        self.interval_seconds = max(60, interval_seconds)
        self.max_compute_seconds = max(1, max_compute_seconds)
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            pairs = self.db.get_org_device_pairs()
            for org_id, device_id in pairs:
                try:
                    compute_device_insights(
                        db=self.db,
                        org_id=org_id,
                        device_id=device_id,
                        max_seconds=self.max_compute_seconds,
                    )
                except ComputeTimeoutError:
                    logger.warning("compute timeout for org=%s device=%s", org_id, device_id)
                except Exception:
                    logger.exception("scheduled compute failed for org=%s device=%s", org_id, device_id)
            self._stop_event.wait(timeout=self.interval_seconds)
