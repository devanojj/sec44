from __future__ import annotations

import logging
import time

from core import build_insight_bundle
from server.db import ServerDatabase

logger = logging.getLogger("endpoint_server.insights")


class ComputeTimeoutError(RuntimeError):
    pass


def compute_device_insights(
    db: ServerDatabase,
    org_id: str,
    device_id: str,
    max_seconds: int = 3,
) -> dict[str, int]:
    start = time.monotonic()
    events = db.fetch_events_for_device(org_id=org_id, device_id=device_id, days=31)
    if not events:
        return {"inserted": 0, "suppressed": 0}
    bundle = build_insight_bundle(events)
    if (time.monotonic() - start) > max_seconds:
        raise ComputeTimeoutError("insight compute exceeded cap")
    stats = db.persist_bundle(org_id=org_id, device_id=device_id, bundle=bundle, dedup_minutes=30)
    return stats
