from __future__ import annotations

import logging

from celery import shared_task

from server.celery_app import celery_app
from server.config import load_config
from server.db import ServerDatabase
from server.insights import ComputeTimeoutError, compute_device_insights
from server.telemetry import INSIGHT_COMPUTE_TIMEOUTS

logger = logging.getLogger("endpoint_server.tasks")


@shared_task(bind=True, name="server.compute_device_insights")
def compute_device_insights_task(self, org_id: str, device_id: str) -> dict[str, int]:  # type: ignore[no-untyped-def]
    config = load_config()
    db = ServerDatabase(config.database_url)
    try:
        return compute_device_insights(
            db=db,
            org_id=org_id,
            device_id=device_id,
            max_seconds=config.max_ingest_compute_seconds,
        )
    except ComputeTimeoutError:
        INSIGHT_COMPUTE_TIMEOUTS.labels(org_id=org_id).inc()
        return {"inserted": 0, "suppressed": 0}


def enqueue_compute(org_id: str, device_id: str) -> bool:
    try:
        celery_app.send_task("server.compute_device_insights", args=[org_id, device_id])
        return True
    except Exception:
        logger.exception("failed to enqueue compute task")
        return False
