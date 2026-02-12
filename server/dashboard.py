from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse

from server.auth import principal_from_request
from server.schemas import Principal

router = APIRouter(tags=["dashboard"])


def _templates(request: Request):
    return request.app.state.templates


def _db(request: Request):
    return request.app.state.db


def _cache(request: Request):
    return request.app.state.cache


def _parse_json(value: str) -> Any:
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return {}


@router.get("/", response_class=HTMLResponse)
@router.get("/overview", response_class=HTMLResponse)
def overview(request: Request, principal: Principal = Depends(principal_from_request)) -> HTMLResponse:
    db = _db(request)
    cache = _cache(request)
    cache_key = f"dash:overview:{principal.org_id}"

    cached = cache.get_json(cache_key)
    if isinstance(cached, dict):
        context = cached
    else:
        fleet = db.fleet_top_devices(org_id=principal.org_id, limit=5)
        alerts_summary = db.list_alert_summary(org_id=principal.org_id)
        for item in fleet:
            item["trend_7d"] = db.get_risk_trend(principal.org_id, item["device_id"], 7)
            item["trend_30d"] = db.get_risk_trend(principal.org_id, item["device_id"], 30)

        context = {
            "fleet": fleet,
            "alerts_summary": alerts_summary,
            "principal": principal.model_dump(mode="json"),
        }
        cache.set_json(cache_key, context, ttl_seconds=30)

    return _templates(request).TemplateResponse(request, "overview.html", context)


@router.get("/fleet", response_class=HTMLResponse)
def fleet_view(request: Request, principal: Principal = Depends(principal_from_request)) -> HTMLResponse:
    db = _db(request)
    fleet = db.fleet_top_devices(org_id=principal.org_id, limit=50)
    for item in fleet:
        item["trend_7d"] = db.get_risk_trend(principal.org_id, item["device_id"], 7)
        item["trend_30d"] = db.get_risk_trend(principal.org_id, item["device_id"], 30)
    return _templates(request).TemplateResponse(
        request,
        "fleet.html",
        {
            "fleet": fleet,
            "principal": principal.model_dump(mode="json"),
        },
    )


@router.get("/insights", response_class=HTMLResponse)
def insights(
    request: Request,
    severity: str | None = Query(default=None),
    source: str | None = Query(default=None),
    status: str | None = Query(default=None),
    device_id: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    principal: Principal = Depends(principal_from_request),
) -> HTMLResponse:
    db = _db(request)
    rows, total = db.list_insights(
        org_id=principal.org_id,
        severity=severity,
        source=source,
        status=status,
        device_id=device_id,
        page=page,
        page_size=page_size,
    )

    insights_data: list[dict[str, Any]] = []
    for row in rows:
        insights_data.append(
            {
                "id": row.id,
                "org_id": row.org_id,
                "device_id": row.device_id,
                "day": row.day,
                "ts": row.ts,
                "insight_type": row.insight_type,
                "source": row.source,
                "severity": row.severity,
                "title": row.title,
                "explanation": row.explanation,
                "evidence": _parse_json(row.evidence_json),
                "status": row.status,
                "count": row.count,
            }
        )

    return _templates(request).TemplateResponse(
        request,
        "insights.html",
        {
            "insights": insights_data,
            "total": total,
            "page": page,
            "page_size": page_size,
            "filters": {
                "severity": severity or "",
                "source": source or "",
                "status": status or "",
                "device_id": device_id or "",
            },
            "principal": principal.model_dump(mode="json"),
        },
    )


@router.get("/events", response_class=HTMLResponse)
def events(
    request: Request,
    severity: str | None = Query(default=None),
    source: str | None = Query(default=None),
    device_id: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    principal: Principal = Depends(principal_from_request),
) -> HTMLResponse:
    db = _db(request)
    rows, total = db.list_events(
        org_id=principal.org_id,
        severity=severity,
        source=source,
        device_id=device_id,
        page=page,
        page_size=page_size,
    )

    events_data: list[dict[str, Any]] = []
    for row in rows:
        events_data.append(
            {
                "id": row.id,
                "org_id": row.org_id,
                "device_id": row.device_id,
                "ts": row.ts,
                "source": row.source,
                "severity": row.severity,
                "platform": row.platform,
                "title": row.title,
                "details": _parse_json(row.details_json),
            }
        )

    return _templates(request).TemplateResponse(
        request,
        "events.html",
        {
            "events": events_data,
            "total": total,
            "page": page,
            "page_size": page_size,
            "filters": {
                "severity": severity or "",
                "source": source or "",
                "device_id": device_id or "",
            },
            "principal": principal.model_dump(mode="json"),
        },
    )


@router.get("/devices", response_class=HTMLResponse)
def devices(request: Request, principal: Principal = Depends(principal_from_request)) -> HTMLResponse:
    db = _db(request)
    items = db.list_devices(org_id=principal.org_id)
    return _templates(request).TemplateResponse(
        request,
        "devices.html",
        {
            "devices": items,
            "principal": principal.model_dump(mode="json"),
        },
    )


@router.get("/devices/{device_id}", response_class=HTMLResponse)
def device_detail(request: Request, device_id: str, principal: Principal = Depends(principal_from_request)) -> HTMLResponse:
    db = _db(request)
    device = db.get_device(org_id=principal.org_id, device_id=device_id)
    metric = db.get_metric(org_id=principal.org_id, device_id=device_id)
    insights, _ = db.list_insights(org_id=principal.org_id, device_id=device_id, page=1, page_size=100)
    events, _ = db.list_events(org_id=principal.org_id, device_id=device_id, page=1, page_size=100)
    trend_7d = db.get_risk_trend(org_id=principal.org_id, device_id=device_id, days=7)
    trend_30d = db.get_risk_trend(org_id=principal.org_id, device_id=device_id, days=30)

    return _templates(request).TemplateResponse(
        request,
        "device_detail.html",
        {
            "device": device,
            "metric": metric,
            "insights": insights,
            "events": events,
            "trend_7d": trend_7d,
            "trend_30d": trend_30d,
            "alerts_summary": db.list_alert_summary(org_id=principal.org_id, device_id=device_id),
            "principal": principal.model_dump(mode="json"),
        },
    )
