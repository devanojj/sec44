from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import psutil

from mac_watchdog.config import AppConfig
from mac_watchdog.db import Database
from mac_watchdog.models import CollectorResult, EventIn, Severity, Source


PROCESS_ATTRS = ["pid", "name", "username", "create_time", "exe"]


def _to_iso(create_time: float | None) -> str | None:
    if not create_time:
        return None
    return datetime.fromtimestamp(create_time, tz=UTC).isoformat()


def _is_unusual_path(exe: str, unusual_paths: list[str]) -> bool:
    exe_path = Path(exe).expanduser().resolve(strict=False)
    return any(str(exe_path).startswith(prefix) for prefix in unusual_paths)


def collect_process_events(config: AppConfig, db: Database) -> CollectorResult:
    events: list[EventIn] = []
    now = datetime.now(UTC).isoformat()
    process_count = 0
    new_processes = 0

    unusual_paths = list(config.unusual_exec_paths)
    unusual_paths.append(str((Path.home() / "Downloads").resolve(strict=False)))

    deny_names = [item.lower() for item in config.deny_process_names]
    allow_paths = config.allow_process_paths

    try:
        iterator = psutil.process_iter(attrs=PROCESS_ATTRS)
    except Exception as exc:  # pragma: no cover - defensive catch
        events.append(
            EventIn(
                source=Source.PROCESS,
                severity=Severity.WARN,
                title="Process collector failed to start",
                details={"error": str(exc)},
            )
        )
        return CollectorResult(events=events)

    for proc in iterator:
        process_count += 1
        try:
            info = proc.info
            pid = info.get("pid")
            name = str(info.get("name") or "unknown")
            username = str(info.get("username") or "unknown")
            exe = str(info.get("exe") or "")
            started = _to_iso(info.get("create_time"))

            process_key = f"{name}|{exe}|{username}"
            is_new = db.touch_process_seen(process_key, now)

            if is_new:
                new_processes += 1
                events.append(
                    EventIn(
                        source=Source.PROCESS,
                        severity=Severity.WARN,
                        title="New process observed",
                        details={
                            "pid": pid,
                            "name": name,
                            "username": username,
                            "exe": exe,
                            "started": started,
                        },
                    )
                )

            if exe and _is_unusual_path(exe, unusual_paths):
                events.append(
                    EventIn(
                        source=Source.PROCESS,
                        severity=Severity.HIGH,
                        title="Process running from unusual path",
                        details={"pid": pid, "name": name, "exe": exe, "username": username},
                    )
                )

            lowered = name.lower()
            if any(pattern in lowered for pattern in deny_names):
                events.append(
                    EventIn(
                        source=Source.PROCESS,
                        severity=Severity.HIGH,
                        title="Denylisted process name observed",
                        details={"pid": pid, "name": name, "username": username, "exe": exe},
                    )
                )

            if allow_paths and exe and not any(allowed in exe for allowed in allow_paths) and is_new:
                events.append(
                    EventIn(
                        source=Source.PROCESS,
                        severity=Severity.WARN,
                        title="Process path not in configured allow list",
                        details={"pid": pid, "name": name, "exe": exe},
                    )
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception as exc:
            events.append(
                EventIn(
                    source=Source.PROCESS,
                    severity=Severity.WARN,
                    title="Process inspection error",
                    details={"error": str(exc)},
                )
            )

    events.append(
        EventIn(
            source=Source.PROCESS,
            severity=Severity.INFO,
            title="Process snapshot completed",
            details={"process_count": process_count, "new_processes": new_processes},
        )
    )
    return CollectorResult(events=events, metadata={"process_count": process_count})
