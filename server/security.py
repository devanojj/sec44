from __future__ import annotations

import time
from datetime import UTC, datetime

from fastapi import HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:  # type: ignore[override]
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; frame-ancestors 'none'; base-uri 'self'; "
            "object-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'"
        )
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        if request.url.scheme == "https" or request.headers.get("x-forwarded-proto", "").lower() == "https":
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        return response


class EnforceHTTPSMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, enabled: bool = True) -> None:  # type: ignore[no-untyped-def]
        super().__init__(app)
        self.enabled = enabled

    async def dispatch(self, request: Request, call_next) -> Response:  # type: ignore[override]
        if not self.enabled:
            return await call_next(request)

        proto = request.headers.get("x-forwarded-proto", "").lower()
        if request.url.scheme != "https" and proto != "https":
            if request.url.path.startswith("/healthz"):
                return JSONResponse(status_code=400, content={"detail": "https_required"})
            https_url = request.url.replace(scheme="https")
            return RedirectResponse(url=str(https_url), status_code=307)
        return await call_next(request)


def parse_timestamp_header(raw: str, window_seconds: int) -> datetime:
    try:
        value = int(raw)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="invalid timestamp header") from exc

    now = int(time.time())
    if abs(now - value) > window_seconds:
        raise HTTPException(status_code=401, detail="request timestamp outside allowed window")
    return datetime.fromtimestamp(value, tz=UTC)
