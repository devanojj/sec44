from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from mac_watchdog.db import Database
from mac_watchdog.scoring import calculate_score_from_counts, classify_score, utc_day_start_iso

router = APIRouter()


def _get_templates(request: Request) -> Jinja2Templates:
    return request.app.state.templates  # type: ignore[no-any-return]


def _get_db(request: Request) -> Database:
    return request.app.state.db  # type: ignore[no-any-return]


@router.get("/", response_class=HTMLResponse)
def overview(request: Request) -> HTMLResponse:
    db = _get_db(request)
    config = request.app.state.config

    today_start = utc_day_start_iso(datetime.now(UTC))
    counts = db.count_events_by_severity(since_ts=today_start)
    score = calculate_score_from_counts(counts, config.severity_weights)
    level = classify_score(score)

    last_run = db.get_app_state("last_run")
    events = db.latest_events(limit=10)
    top_alerts = [item for item in events if item["severity"] in {"WARN", "HIGH"}][:5]

    templates = _get_templates(request)
    return templates.TemplateResponse(
        request,
        "overview.html",
        {
            "last_run": last_run,
            "counts": counts,
            "score": score,
            "score_level": level,
            "top_alerts": top_alerts,
        },
    )


@router.get("/events", response_class=HTMLResponse)
def events_page(
    request: Request,
    severity: str | None = None,
    source: str | None = None,
    start: str | None = None,
    end: str | None = None,
    page: int = 1,
) -> HTMLResponse:
    db = _get_db(request)
    page_size = 50
    events = db.get_events(
        severity=severity,
        source=source,
        start_ts=start,
        end_ts=end,
        page=page,
        page_size=page_size,
    )
    templates = _get_templates(request)
    context: dict[str, Any] = {
        "events": events,
        "page": page,
        "page_size": page_size,
        "filters": {
            "severity": severity or "",
            "source": source or "",
            "start": start or "",
            "end": end or "",
        },
    }
    return templates.TemplateResponse(request, "events.html", context)


@router.get("/listeners", response_class=HTMLResponse)
def listeners_page(request: Request) -> HTMLResponse:
    db = _get_db(request)
    snapshot = db.get_latest_snapshot("network_listeners")
    listeners = snapshot["blob"] if snapshot else []
    ts = snapshot["ts"] if snapshot else None

    templates = _get_templates(request)
    return templates.TemplateResponse(
        request,
        "listeners.html",
        {
            "snapshot_ts": ts,
            "listeners": listeners,
        },
    )


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request) -> HTMLResponse:
    config = request.app.state.config

    raw = config.model_dump()
    redacted: dict[str, Any] = {}
    for key, value in raw.items():
        if any(token in key.lower() for token in ("secret", "token", "password", "key")):
            redacted[key] = "***REDACTED***"
        else:
            redacted[key] = value

    templates = _get_templates(request)
    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "settings": redacted,
            "data_dir": str(config.data_dir),
            "db_path": str(config.db_path),
        },
    )
