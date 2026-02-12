from __future__ import annotations

from datetime import UTC, datetime

from shared.enums import Platform, Severity, Source
from shared.schemas import EventEnvelope


class WindowsAuthCollector:
    """Best-effort Windows Event Log auth collector with graceful fallback."""

    def __init__(self, max_events: int = 50) -> None:
        self.max_events = max_events

    def collect(self) -> list[EventEnvelope]:
        try:
            import win32evtlog  # type: ignore[import-not-found]
        except Exception:
            return [
                EventEnvelope(
                    ts=datetime.now(UTC),
                    source=Source.SYSTEM,
                    severity=Severity.WARN,
                    platform=Platform.WINDOWS,
                    title="windows_eventlog_unavailable",
                    details_json={"reason": "pywin32_not_installed"},
                )
            ]

        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        handle = None
        try:
            handle = win32evtlog.OpenEventLog(None, "Security")
            records = win32evtlog.ReadEventLog(handle, flags, 0)
        except Exception as exc:
            return [
                EventEnvelope(
                    ts=datetime.now(UTC),
                    source=Source.SYSTEM,
                    severity=Severity.WARN,
                    platform=Platform.WINDOWS,
                    title="windows_eventlog_access_denied",
                    details_json={"reason": str(exc.__class__.__name__)},
                )
            ]
        finally:
            if handle is not None:
                try:
                    win32evtlog.CloseEventLog(handle)
                except Exception:
                    pass

        events: list[EventEnvelope] = []
        for event in records or []:
            if len(events) >= self.max_events:
                break
            event_id = int(event.EventID & 0xFFFF)
            if event_id not in {4624, 4625}:
                continue
            inserts = getattr(event, "StringInserts", None) or []
            username = "unknown"
            if isinstance(inserts, list) and len(inserts) > 5 and inserts[5]:
                username = str(inserts[5])

            if event_id == 4625:
                severity = Severity.WARN
                event_type = "failed_login"
            else:
                severity = Severity.INFO
                event_type = "successful_login"

            events.append(
                EventEnvelope(
                    ts=datetime.now(UTC),
                    source=Source.AUTH,
                    severity=severity,
                    platform=Platform.WINDOWS,
                    title=f"windows_{event_type}",
                    details_json={
                        "event_type": event_type,
                        "event_id": event_id,
                        "username": username,
                    },
                )
            )

        return events
