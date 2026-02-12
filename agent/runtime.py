from __future__ import annotations

import logging
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agent.collectors.factory import build_collectors, current_platform
from agent.config import AgentConfig, default_spool_path
from agent.spool import Spooler
from agent.sender import Sender
from shared.constants import MAX_EVENTS_PER_BATCH, MAX_PAYLOAD_BYTES
from shared.enums import Severity, Source
from shared.schemas import EventEnvelope, IngestRequest
from shared.serialization import canonical_json_bytes

logger = logging.getLogger("endpoint_agent.runtime")


def _collector_failure_event(platform: str, collector_name: str, error: Exception) -> EventEnvelope:
    return EventEnvelope(
        ts=datetime.now(UTC),
        source=Source.SYSTEM,
        severity=Severity.WARN,
        platform=current_platform(),
        title="collector_failure",
        details_json={
            "collector": collector_name,
            "platform": platform,
            "reason": error.__class__.__name__,
        },
    )


def collect_events(config: AgentConfig) -> list[EventEnvelope]:
    events: list[EventEnvelope] = []
    platform_name = current_platform().value
    collectors = build_collectors(config)
    for collector in collectors:
        try:
            collected = collector.collect()
            events.extend(collected)
        except Exception as exc:
            logger.exception("collector failed: %s", collector.__class__.__name__)
            events.append(_collector_failure_event(platform_name, collector.__class__.__name__, exc))
    events.extend(_failed_login_spike_events(events, config))
    return events


def _failed_login_spike_events(events: list[EventEnvelope], config: AgentConfig) -> list[EventEnvelope]:
    threshold_raw = config.platform.get("failed_login_spike_threshold", 5)
    try:
        threshold = max(1, int(threshold_raw))
    except (TypeError, ValueError):
        threshold = 5

    failed = 0
    for event in events:
        if event.source != Source.AUTH:
            continue
        lowered_title = event.title.lower()
        event_type = str(event.details_json.get("event_type", "")).lower()
        if "failed" in lowered_title or event_type == "failed_login":
            failed += 1

    if failed < threshold:
        return []

    rate_per_minute = round(failed / max(1, config.interval_seconds / 60.0), 2)
    severity = Severity.HIGH if failed >= threshold * 2 else Severity.WARN
    return [
        EventEnvelope(
            ts=datetime.now(UTC),
            source=Source.AUTH,
            severity=severity,
            platform=current_platform(),
            title="failed_login_spike",
            details_json={
                "event_type": "failed_login_spike",
                "failed_count": failed,
                "threshold": threshold,
                "window_seconds": config.interval_seconds,
                "rate_per_minute": rate_per_minute,
            },
        )
    ]


def _request_size_for(events: list[EventEnvelope], config: AgentConfig) -> int:
    req = IngestRequest(
        org_id=config.org_id,
        device_id=config.device_id,
        agent_version=config.agent_version,
        sent_at=datetime.now(UTC),
        nonce="n" * 32,
        events=events,
    )
    return len(canonical_json_bytes(req))


def split_batches(events: list[EventEnvelope], config: AgentConfig) -> list[list[EventEnvelope]]:
    if not events:
        return []

    max_events = min(config.max_batch_events, MAX_EVENTS_PER_BATCH)
    batches: list[list[EventEnvelope]] = []
    current: list[EventEnvelope] = []

    for event in events:
        candidate = current + [event]
        candidate_size = _request_size_for(candidate, config)
        if current and (len(candidate) > max_events or candidate_size > MAX_PAYLOAD_BYTES):
            batches.append(current)
            current = [event]
        else:
            current = candidate

    if current:
        batches.append(current)
    return batches


def run_once(config: AgentConfig, spool_path: Path | None = None) -> dict[str, Any]:
    spooler = Spooler(spool_path or default_spool_path(), max_batches=config.spool_max_batches)
    sender = Sender(config)
    try:
        events = collect_events(config)
        batches = split_batches(events, config)
        dropped = 0
        for batch in batches:
            spooler.enqueue(batch)
        dropped += spooler.enforce_limit()
        sent, failed = sender.send_due(spooler)
        return {
            "collected_events": len(events),
            "queued_batches": len(batches),
            "sent_batches": sent,
            "failed_batches": failed,
            "dropped_batches": dropped,
            "spool_depth": spooler.count(),
        }
    finally:
        spooler.close()


def run_daemon(config: AgentConfig, stop_event: threading.Event, spool_path: Path | None = None) -> None:
    while not stop_event.is_set():
        try:
            summary = run_once(config, spool_path=spool_path)
            logger.info("cycle summary=%s", summary)
        except Exception:
            logger.exception("daemon cycle failed")
        stop_event.wait(timeout=config.interval_seconds)
