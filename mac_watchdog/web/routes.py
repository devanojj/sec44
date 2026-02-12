from __future__ import annotations

import json
from datetime import UTC, date, datetime, timedelta
from statistics import mean
from typing import Any

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from mac_watchdog.db import Database
from mac_watchdog.insights import InsightEngine
from mac_watchdog.insights.baseline import SIGNAL_KEYS
from mac_watchdog.insights.brief import compose_daily_brief
from mac_watchdog.insights.deltas import compute_new_resolved
from mac_watchdog.insights.schemas import (
    BaselineClassification,
    BaselineDelta,
    InsightSeverity,
    InsightSource,
    InsightStatus,
)
from mac_watchdog.models import Severity, Source
from mac_watchdog.services.action_queue import ActionQueueService
from mac_watchdog.services.insight_service import InsightService
from mac_watchdog.services.metrics_service import MetricsService

router = APIRouter()


def _get_templates(request: Request) -> Jinja2Templates:
    return request.app.state.templates  # type: ignore[no-any-return]


def _get_db(request: Request) -> Database:
    return request.app.state.db  # type: ignore[no-any-return]


def _get_metrics_service(request: Request) -> MetricsService:
    db = _get_db(request)
    config = request.app.state.config
    return MetricsService(db, config.severity_weights)


def _get_insight_service(request: Request) -> InsightService:
    return InsightService(_get_db(request))


def _get_action_queue_service(request: Request) -> ActionQueueService:
    return ActionQueueService(_get_insight_service(request))


def _get_engine(request: Request) -> InsightEngine:
    return request.app.state.insight_engine  # type: ignore[no-any-return]


def _parse_json(value: str | None) -> dict[str, Any]:
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _to_utc_iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat()


def _parse_deltas(raw: dict[str, Any], signal_counts: dict[str, int]) -> list[BaselineDelta]:
    output: list[BaselineDelta] = []
    for signal in SIGNAL_KEYS:
        item = raw.get(signal)
        if isinstance(item, dict):
            try:
                output.append(BaselineDelta.model_validate(item))
                continue
            except Exception:
                pass
        output.append(
            BaselineDelta(
                signal=signal,  # type: ignore[arg-type]
                today=int(signal_counts.get(signal, 0)),
                baseline=0.0,
                ratio=float(signal_counts.get(signal, 0)),
                classification=BaselineClassification.NORMAL,
            )
        )
    return output


def _compute_trend(metrics: list[Any], today_metric: Any) -> dict[str, Any]:
    recent = metrics[-7:]
    risk_values = [metric.risk_score for metric in recent]
    high_values = [metric.high_count for metric in recent]

    avg_risk = mean(risk_values) if risk_values else float(today_metric.risk_score)
    avg_high = mean(high_values) if high_values else float(today_metric.high_count)

    status = "Stable"
    if today_metric.risk_score <= avg_risk * 0.9 and today_metric.high_count <= avg_high * 0.9:
        status = "Improving"
    elif today_metric.risk_score >= avg_risk * 1.1 or today_metric.high_count >= avg_high * 1.1:
        status = "Regressing"

    return {
        "risk_score_today": today_metric.risk_score,
        "risk_score_7d_avg": round(avg_risk, 2),
        "high_alerts_today": today_metric.high_count,
        "high_alerts_7d_avg": round(avg_high, 2),
        "status": status,
        "high_alert_series_7d": high_values,
    }


@router.get("/", response_class=HTMLResponse)
@router.get("/overview", response_class=HTMLResponse)
def overview(request: Request) -> HTMLResponse:
    db = _get_db(request)
    metrics_service = _get_metrics_service(request)
    insight_service = _get_insight_service(request)
    action_service = _get_action_queue_service(request)

    today = datetime.now(UTC).date()
    day_text = today.isoformat()

    metric = metrics_service.get_metrics(day_text)
    if metric is None:
        try:
            _get_engine(request).generate_cycle()
        except Exception:
            pass
        metric = metrics_service.get_metrics(day_text)

    if metric is None:
        class _Fallback:
            risk_score = 0
            high_count = 0
            warn_count = 0
            info_count = 0
            failed_logins = 0
            new_listeners = 0
            new_processes = 0
            suspicious_execs = 0
            baseline_deltas = {}
            drivers: list[Any] = []

        metric = _Fallback()

    signal_counts = {
        "failed_logins_24h": metric.failed_logins,
        "new_listeners_24h": metric.new_listeners,
        "new_processes_24h": metric.new_processes,
        "suspicious_exec_path_24h": metric.suspicious_execs,
    }

    baseline_deltas = _parse_deltas(metric.baseline_deltas, signal_counts)

    brief_raw = _parse_json(db.get_app_state(f"daily_brief:{day_text}"))
    recent_metrics = metrics_service.list_recent_metrics(7, end_date=today)
    drivers = sorted(metric.drivers, key=lambda item: item.percent, reverse=True)

    if brief_raw:
        daily_brief = brief_raw
    else:
        queue = action_service.top_actions(limit=5)
        brief = compose_daily_brief(
            date_value=day_text,
            risk_score=metric.risk_score,
            recent_risk_scores=[item.risk_score for item in recent_metrics],
            drivers=drivers,
            baseline_deltas={item.signal: item for item in baseline_deltas},
            action_texts=[str(item["action"]) for item in queue],
            extra_titles=[],
        )
        daily_brief = brief.model_dump()

    delta_panel = _parse_json(db.get_app_state(f"daily_delta:{day_text}"))
    if not delta_panel:
        today_events = metrics_service.events_for_day(today)
        yesterday_events = metrics_service.events_for_day(today - timedelta(days=1))
        new_risks, resolved_risks, _ = compute_new_resolved(today_events, yesterday_events)
        delta_panel = {"new_risks": new_risks[:10], "resolved_risks": resolved_risks[:10]}

    trend = _compute_trend(recent_metrics, metric)
    action_queue = action_service.top_actions(limit=5)
    insights = insight_service.list_insights(page=1, page_size=8)

    templates = _get_templates(request)
    return templates.TemplateResponse(
        request,
        "overview.html",
        {
            "last_run": db.get_app_state("last_run"),
            "daily_brief": daily_brief,
            "action_queue": action_queue,
            "drivers": drivers,
            "delta_panel": delta_panel,
            "baseline_deltas": baseline_deltas,
            "trend": trend,
            "insights_preview": insights,
            "counts": {
                "INFO": metric.info_count,
                "WARN": metric.warn_count,
                "HIGH": metric.high_count,
            },
        },
    )


@router.get("/insights", response_class=HTMLResponse)
def insights_page(
    request: Request,
    severity: InsightSeverity | None = Query(default=None),
    source: InsightSource | None = Query(default=None),
    status: InsightStatus | None = Query(default=None),
    start: datetime | None = Query(default=None),
    end: datetime | None = Query(default=None),
    page: int = Query(default=1, ge=1, le=5000),
) -> HTMLResponse:
    insight_service = _get_insight_service(request)

    records = insight_service.list_insights(
        severity=severity.value if severity else None,
        source=source.value if source else None,
        status=status.value if status else None,
        start_ts=_to_utc_iso(start),
        end_ts=_to_utc_iso(end),
        page=page,
        page_size=30,
    )

    templates = _get_templates(request)
    return templates.TemplateResponse(
        request,
        "insights.html",
        {
            "insights": records,
            "page": page,
            "page_size": 30,
            "filters": {
                "severity": severity.value if severity else "",
                "source": source.value if source else "",
                "status": status.value if status else "",
                "start": start.isoformat() if start else "",
                "end": end.isoformat() if end else "",
            },
        },
    )


@router.get("/events", response_class=HTMLResponse)
def events_page(
    request: Request,
    severity: Severity | None = Query(default=None),
    source: Source | None = Query(default=None),
    start: datetime | None = Query(default=None),
    end: datetime | None = Query(default=None),
    page: int = Query(default=1, ge=1, le=5000),
) -> HTMLResponse:
    db = _get_db(request)
    page_size = 50
    events = db.get_events(
        severity=severity.value if severity else None,
        source=source.value if source else None,
        start_ts=_to_utc_iso(start),
        end_ts=_to_utc_iso(end),
        page=page,
        page_size=page_size,
    )
    templates = _get_templates(request)
    context: dict[str, Any] = {
        "events": events,
        "page": page,
        "page_size": page_size,
        "filters": {
            "severity": severity.value if severity else "",
            "source": source.value if source else "",
            "start": start.isoformat() if start else "",
            "end": end.isoformat() if end else "",
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
