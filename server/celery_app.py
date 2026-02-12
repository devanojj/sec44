from __future__ import annotations

import os

from celery import Celery


def _redis_url() -> str:
    return os.getenv("REDIS_URL", "redis://localhost:6379/0")


celery_app = Celery(
    "endpoint_monitor",
    broker=_redis_url(),
    backend=_redis_url(),
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_track_started=True,
    task_time_limit=int(os.getenv("EM_CELERY_TASK_TIME_LIMIT", "30")),
    worker_prefetch_multiplier=1,
)

celery_app.autodiscover_tasks(["server"])
