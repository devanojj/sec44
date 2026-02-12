from __future__ import annotations

from datetime import UTC

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from server.security import parse_timestamp_header
from server.tasks import enqueue_compute
from server.telemetry import INGEST_ACCEPTED, INGEST_REJECTED
from shared.schemas import IngestRequest, IngestResponse
from shared.signing import (
    HEADER_DEVICE,
    HEADER_NONCE,
    HEADER_ORG,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    SignatureError,
    verify_request,
)

router = APIRouter(prefix="", tags=["ingest"])


@router.post("/ingest", response_model=IngestResponse)
async def ingest(request: Request) -> JSONResponse:
    config = request.app.state.config
    db = request.app.state.db
    limiter = request.app.state.rate_limiter
    signing_keys: dict[str, str] = request.app.state.signing_keys

    headers = {
        HEADER_ORG: request.headers.get(HEADER_ORG, ""),
        HEADER_DEVICE: request.headers.get(HEADER_DEVICE, ""),
        HEADER_TIMESTAMP: request.headers.get(HEADER_TIMESTAMP, ""),
        HEADER_NONCE: request.headers.get(HEADER_NONCE, ""),
        HEADER_SIGNATURE: request.headers.get(HEADER_SIGNATURE, ""),
    }
    for key, value in headers.items():
        if not value:
            raise HTTPException(status_code=400, detail=f"missing required header: {key}")

    org_id = headers[HEADER_ORG]
    org = db.get_org(org_id)
    if org is None or not org.is_active:
        INGEST_REJECTED.labels(org_id=org_id, reason="unknown_org").inc()
        raise HTTPException(status_code=401, detail="unknown or inactive org")

    allowed = limiter.allow(key=f"ingest:{org_id}", limit=int(org.ingest_rate_limit_per_minute), window_seconds=60)
    if not allowed:
        INGEST_REJECTED.labels(org_id=org_id, reason="rate_limit").inc()
        raise HTTPException(status_code=429, detail="rate limit exceeded")

    body = await request.body()
    if len(body) == 0:
        INGEST_REJECTED.labels(org_id=org_id, reason="empty_body").inc()
        raise HTTPException(status_code=400, detail="empty request body")
    if len(body) > config.max_payload_bytes:
        INGEST_REJECTED.labels(org_id=org_id, reason="payload_too_large").inc()
        raise HTTPException(status_code=413, detail="payload too large")

    api_key = signing_keys.get(org_id)
    if not api_key:
        INGEST_REJECTED.labels(org_id=org_id, reason="missing_signing_key").inc()
        raise HTTPException(status_code=401, detail="org signing key not configured")

    if db.hash_secret(api_key) != org.api_key_hash:
        INGEST_REJECTED.labels(org_id=org_id, reason="org_key_mismatch").inc()
        raise HTTPException(status_code=401, detail="org signing key mismatch")

    try:
        valid_sig = verify_request(body=body, headers=headers, api_key=api_key)
    except SignatureError as exc:
        INGEST_REJECTED.labels(org_id=org_id, reason="signature_error").inc()
        raise HTTPException(status_code=401, detail=f"signature error: {exc}") from exc

    if not valid_sig:
        INGEST_REJECTED.labels(org_id=org_id, reason="invalid_signature").inc()
        raise HTTPException(status_code=401, detail="invalid signature")

    seen_at = parse_timestamp_header(headers[HEADER_TIMESTAMP], config.replay_window_seconds)

    try:
        payload = IngestRequest.model_validate_json(body)
    except Exception as exc:
        INGEST_REJECTED.labels(org_id=org_id, reason="invalid_schema").inc()
        raise HTTPException(status_code=422, detail="invalid payload schema") from exc

    if payload.org_id != headers[HEADER_ORG]:
        INGEST_REJECTED.labels(org_id=org_id, reason="org_mismatch").inc()
        raise HTTPException(status_code=400, detail="org header/body mismatch")
    if payload.device_id != headers[HEADER_DEVICE]:
        INGEST_REJECTED.labels(org_id=org_id, reason="device_mismatch").inc()
        raise HTTPException(status_code=400, detail="device header/body mismatch")
    if payload.nonce != headers[HEADER_NONCE]:
        INGEST_REJECTED.labels(org_id=org_id, reason="nonce_mismatch").inc()
        raise HTTPException(status_code=400, detail="nonce header/body mismatch")

    sent_at = payload.sent_at.astimezone(UTC) if payload.sent_at.tzinfo else payload.sent_at.replace(tzinfo=UTC)
    if abs((seen_at - sent_at).total_seconds()) > config.replay_window_seconds:
        INGEST_REJECTED.labels(org_id=org_id, reason="timestamp_skew").inc()
        raise HTTPException(status_code=401, detail="sent_at outside allowed replay window")

    accepted = db.ingest_request(request=payload, seen_at=seen_at, window_seconds=config.replay_window_seconds)
    if accepted == -1:
        INGEST_REJECTED.labels(org_id=org_id, reason="org_invalid").inc()
        raise HTTPException(status_code=401, detail="unknown org")
    if accepted == 0:
        INGEST_REJECTED.labels(org_id=org_id, reason="replay_nonce").inc()
        raise HTTPException(status_code=409, detail="replay nonce rejected")

    enqueue_compute(org_id=payload.org_id, device_id=payload.device_id)
    INGEST_ACCEPTED.labels(org_id=org_id).inc(accepted)

    response = IngestResponse(accepted=accepted, rejected=0)
    return JSONResponse(content=response.model_dump(mode="json"))
