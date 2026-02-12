from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from shared.constants import MAX_EVENTS_PER_BATCH
from shared.enums import Platform, Severity, Source
from shared.schemas import EventEnvelope, IngestRequest


def test_event_count_limit_enforced() -> None:
    event = EventEnvelope(
        ts=datetime.now(UTC),
        source=Source.SYSTEM,
        severity=Severity.INFO,
        platform=Platform.MACOS,
        title="ok",
        details_json={"k": "v"},
    )

    with pytest.raises(ValidationError):
        IngestRequest(
            org_id="dev-org",
            device_id="device-1",
            agent_version="0.2.0",
            sent_at=datetime.now(UTC),
            nonce="c" * 32,
            events=[event for _ in range(MAX_EVENTS_PER_BATCH + 1)],
        )
