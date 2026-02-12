from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime

from shared.enums import Platform, Severity, Source
from shared.schemas import EventEnvelope


class MacOSAuthCollector:
    """Collects best-effort login/authentication signals from macOS unified logs."""

    LOG_BIN = "/usr/bin/log"
    FIXED_ARGS = [
        LOG_BIN,
        "show",
        "--style",
        "json",
        "--last",
        "5m",
        "--predicate",
        '(eventMessage CONTAINS[c] "authentication" OR eventMessage CONTAINS[c] "login")',
    ]

    def __init__(self, max_events: int = 50) -> None:
        self.max_events = max_events

    def collect(self) -> list[EventEnvelope]:
        try:
            result = subprocess.run(
                self.FIXED_ARGS,
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
        except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired, OSError) as exc:
            return [
                EventEnvelope(
                    ts=datetime.now(UTC),
                    source=Source.SYSTEM,
                    severity=Severity.WARN,
                    platform=Platform.MACOS,
                    title="macos_auth_collection_unavailable",
                    details_json={"reason": str(exc.__class__.__name__)},
                )
            ]

        if result.returncode != 0:
            return [
                EventEnvelope(
                    ts=datetime.now(UTC),
                    source=Source.SYSTEM,
                    severity=Severity.WARN,
                    platform=Platform.MACOS,
                    title="macos_auth_collection_failed",
                    details_json={"return_code": result.returncode},
                )
            ]

        events: list[EventEnvelope] = []
        for line in result.stdout.splitlines():
            if len(events) >= self.max_events:
                break
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict):
                continue

            message = str(record.get("eventMessage") or "")
            lowered = message.lower()
            if "auth" not in lowered and "login" not in lowered:
                continue

            event_type = "auth_event"
            severity = Severity.INFO
            if "fail" in lowered or "invalid" in lowered:
                event_type = "failed_login"
                severity = Severity.WARN
            elif "success" in lowered or "accepted" in lowered:
                event_type = "successful_login"

            user = str(record.get("userName") or record.get("senderImagePath") or "unknown")
            events.append(
                EventEnvelope(
                    ts=datetime.now(UTC),
                    source=Source.AUTH,
                    severity=severity,
                    platform=Platform.MACOS,
                    title=f"macos_{event_type}",
                    details_json={
                        "event_type": event_type,
                        "username": user,
                        "message": message[:512],
                    },
                )
            )

        return events
