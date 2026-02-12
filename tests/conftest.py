from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from server.app import create_app
from server.config import OrgSeed, ServerConfig, UserSeed
from shared.enums import Platform, Severity, Source
from shared.schemas import EventEnvelope, IngestRequest
from shared.serialization import canonical_json_bytes
from shared.signing import build_signed_headers


@pytest.fixture()
def server_config(tmp_path: Path) -> ServerConfig:
    return ServerConfig(
        environment="test",
        database_url=f"sqlite:///{str(tmp_path / 'server.db')}",
        redis_url="redis://127.0.0.1:6399/0",
        host="127.0.0.1",
        port=8000,
        dev_enable_docs=False,
        enforce_https=False,
        replay_window_seconds=300,
        max_ingest_compute_seconds=3,
        max_payload_bytes=512 * 1024,
        jwt_access_secret="test-access-secret",
        jwt_refresh_secret="test-refresh-secret",
        jwt_issuer="test-issuer",
        jwt_audience="test-audience",
        access_token_ttl_seconds=900,
        refresh_token_ttl_seconds=3600,
        metrics_token="",
        csrf_secret="test-csrf-secret",
        org_seeds=[OrgSeed(org_id="dev-org", org_name="Development", api_key="test-api-key", ingest_rate_limit_per_minute=120)],
        user_seeds=[UserSeed(org_id="dev-org", username="admin", password="ChangeMeNow!123", role="admin")],
    )


@pytest.fixture()
def client(server_config: ServerConfig):
    app = create_app(server_config)
    with TestClient(app) as tc:
        yield tc


def signed_ingest_request(
    api_key: str,
    *,
    nonce: str | None = None,
    event_count: int = 1,
    timestamp: int | None = None,
) -> tuple[bytes, dict[str, str]]:
    actual_nonce = nonce or ("a" * 32)
    events = [
        EventEnvelope(
            ts=datetime.now(UTC),
            source=Source.AUTH,
            severity=Severity.WARN,
            platform=Platform.MACOS,
            title="failed_login",
            details_json={"event_type": "failed_login", "username": "alice"},
        )
        for _ in range(event_count)
    ]
    body = IngestRequest(
        org_id="dev-org",
        device_id="device-001",
        agent_version="0.2.0",
        sent_at=datetime.now(UTC),
        nonce=actual_nonce,
        events=events,
    )
    raw = canonical_json_bytes(body)
    headers = build_signed_headers(
        body=body,
        api_key=api_key,
        org_id="dev-org",
        device_id="device-001",
        timestamp=int(time.time()) if timestamp is None else int(timestamp),
        nonce=actual_nonce,
    )
    headers["Content-Type"] = "application/json"
    return raw, headers


@pytest.fixture()
def signed_ingest():
    return signed_ingest_request
