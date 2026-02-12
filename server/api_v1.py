from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from server.auth import principal_from_request, require_role
from server.auth import AuthManager
from server.config import UserSeed
from server.schemas import CreateUserRequest, MetricsQuery, Principal

router = APIRouter(prefix="/v1", tags=["api"])


@router.get("/metrics")
def metrics(
    request: Request,
    org_id: str = Query(..., min_length=1, max_length=256),
    device_id: str | None = Query(default=None, max_length=256),
    page: int = Query(default=1, ge=1, le=100000),
    page_size: int = Query(default=25, ge=1, le=200),
    principal: Principal = Depends(require_role({"admin", "read_only"})),
) -> JSONResponse:
    if principal.org_id != org_id:
        raise HTTPException(status_code=403, detail="cross-org access denied")

    query = MetricsQuery(org_id=org_id, device_id=device_id, page=page, page_size=page_size)
    db = request.app.state.db
    cache = request.app.state.cache
    limiter = request.app.state.rate_limiter

    org = db.get_org(org_id)
    if org is None or not org.is_active:
        raise HTTPException(status_code=404, detail="org not found")

    if not limiter.allow(
        key=f"api:{principal.org_id}:{principal.user_id}",
        limit=max(30, int(org.ingest_rate_limit_per_minute)),
        window_seconds=60,
    ):
        raise HTTPException(status_code=429, detail="api rate limit exceeded")

    cache_key = f"api:v1:metrics:{query.org_id}:{query.device_id or 'all'}:{query.page}:{query.page_size}"
    cached = cache.get_json(cache_key)
    if isinstance(cached, dict):
        return JSONResponse(content=cached)

    rows, total = db.metrics_page(
        org_id=query.org_id,
        page=query.page,
        page_size=query.page_size,
        device_id=query.device_id,
    )

    payload = {
        "org_id": query.org_id,
        "page": query.page,
        "page_size": query.page_size,
        "total": total,
        "items": rows,
        "alerts_summary": db.list_alert_summary(org_id=query.org_id, device_id=query.device_id),
    }
    cache.set_json(cache_key, payload, ttl_seconds=20)
    return JSONResponse(content=payload)


@router.get("/fleet/top")
def fleet_top(
    request: Request,
    org_id: str = Query(..., min_length=1, max_length=256),
    limit: int = Query(default=5, ge=1, le=50),
    principal: Principal = Depends(principal_from_request),
) -> JSONResponse:
    if principal.org_id != org_id:
        raise HTTPException(status_code=403, detail="cross-org access denied")

    fleet = request.app.state.db.fleet_top_devices(org_id=org_id, limit=limit)
    return JSONResponse(content={"org_id": org_id, "items": fleet})


@router.post("/admin/users")
def create_user(
    request: Request,
    payload: CreateUserRequest,
    principal: Principal = Depends(require_role({"admin"})),
) -> JSONResponse:
    if payload.org_id != principal.org_id:
        raise HTTPException(status_code=403, detail="cross-org user create denied")
    role = payload.role if payload.role in {"admin", "read_only"} else "read_only"
    db = request.app.state.db
    auth: AuthManager = request.app.state.auth
    db.seed_users(
        [UserSeed(org_id=payload.org_id, username=payload.username, password=payload.password, role=role)],
        auth.hash_password,
    )
    return JSONResponse(content={"created": True, "org_id": payload.org_id, "username": payload.username, "role": role})
