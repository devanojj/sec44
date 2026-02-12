from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from server.config import OrgSeed
from server.db import ServerDatabase
from shared.enums import Platform, Severity, Source
from shared.schemas import EventEnvelope, IngestRequest


def test_sql_parameterization_blocks_injection_strings(tmp_path: Path) -> None:
    db = ServerDatabase(f"sqlite:///{str(tmp_path / 'db.sqlite3')}")
    db.init_for_tests()
    db.seed_orgs([OrgSeed(org_id="dev-org", org_name="Dev", api_key="k", ingest_rate_limit_per_minute=60)])

    payload = IngestRequest(
        org_id="dev-org",
        device_id="d1",
        agent_version="0.2.0",
        sent_at=datetime.now(UTC),
        nonce="n" * 32,
        events=[
            EventEnvelope(
                ts=datetime.now(UTC),
                source=Source.PROCESS,
                severity=Severity.INFO,
                platform=Platform.MACOS,
                title="x'); DROP TABLE events; --",
                details_json={"process_name": "safe"},
            )
        ],
    )
    inserted = db.ingest_request(payload, seen_at=datetime.now(UTC), window_seconds=300)
    assert inserted == 1

    rows, total = db.list_events(org_id="dev-org", page=1, page_size=10)
    assert total == 1
    assert len(rows) == 1


def test_replay_nonce_rejected(client, signed_ingest) -> None:
    body, headers = signed_ingest("test-api-key", nonce="b" * 32)
    first = client.post("/ingest", content=body, headers=headers)
    assert first.status_code == 200

    second = client.post("/ingest", content=body, headers=headers)
    assert second.status_code == 409
