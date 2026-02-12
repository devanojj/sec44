from __future__ import annotations

import time

from fastapi import APIRouter, HTTPException, Request
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

REQUEST_COUNT = Counter(
    "endpoint_monitor_http_requests_total",
    "Total HTTP requests",
    ["method", "path", "status"],
)
REQUEST_LATENCY = Histogram(
    "endpoint_monitor_http_request_duration_seconds",
    "Request duration seconds",
    ["method", "path"],
)
INGEST_ACCEPTED = Counter("endpoint_monitor_ingest_accepted_total", "Accepted events", ["org_id"])
INGEST_REJECTED = Counter("endpoint_monitor_ingest_rejected_total", "Rejected events", ["org_id", "reason"])
INSIGHT_COMPUTE_TIMEOUTS = Counter("endpoint_monitor_compute_timeouts_total", "Insight compute timeouts", ["org_id"])


class MetricsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:  # type: ignore[override]
        start = time.monotonic()
        response = await call_next(request)
        duration = time.monotonic() - start
        method = request.method
        path = request.url.path
        REQUEST_COUNT.labels(method=method, path=path, status=str(response.status_code)).inc()
        REQUEST_LATENCY.labels(method=method, path=path).observe(duration)
        return response


router = APIRouter()


@router.get("/internal/metrics")
def metrics(request: Request) -> Response:
    token = request.app.state.config.metrics_token
    if token:
        supplied = request.headers.get("X-Metrics-Token", "")
        if supplied != token:
            raise HTTPException(status_code=401, detail="metrics token required")
    payload = generate_latest()
    return Response(content=payload, media_type=CONTENT_TYPE_LATEST)
