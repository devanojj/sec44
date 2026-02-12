from __future__ import annotations

import time

from server.config import OrgSeed
from shared.constants import MAX_PAYLOAD_BYTES


def test_invalid_signature_rejected(client, signed_ingest) -> None:
    body, headers = signed_ingest("test-api-key", nonce="e" * 32)
    headers["X-EM-Signature"] = "0" * 64
    response = client.post("/ingest", content=body, headers=headers)
    assert response.status_code == 401


def test_expired_timestamp_rejected(client, signed_ingest) -> None:
    body, headers = signed_ingest("test-api-key", nonce="f" * 32, timestamp=int(time.time()) - 10000)
    response = client.post("/ingest", content=body, headers=headers)
    assert response.status_code == 401


def test_oversized_payload_rejected(client, signed_ingest) -> None:
    _, headers = signed_ingest("test-api-key", nonce="g" * 32)
    huge = b"{" + (b"a" * (MAX_PAYLOAD_BYTES + 10)) + b"}"
    response = client.post("/ingest", content=huge, headers=headers)
    assert response.status_code == 413


def test_rate_limit_applied_per_org(client, signed_ingest) -> None:
    client.app.state.db.seed_orgs(
        [OrgSeed(org_id="dev-org", org_name="Development", api_key="test-api-key", ingest_rate_limit_per_minute=1)]
    )
    body_a, headers_a = signed_ingest("test-api-key", nonce="h" * 32)
    body_b, headers_b = signed_ingest("test-api-key", nonce="i" * 32)

    first = client.post("/ingest", content=body_a, headers=headers_a)
    second = client.post("/ingest", content=body_b, headers=headers_b)

    assert first.status_code == 200
    assert second.status_code == 429
