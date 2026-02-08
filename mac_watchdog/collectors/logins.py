from __future__ import annotations

import subprocess

from mac_watchdog.config import AppConfig
from mac_watchdog.db import Database
from mac_watchdog.models import CollectorResult, EventIn, Severity, Source

LOG_CMD = [
    "/usr/bin/log",
    "show",
    "--style",
    "syslog",
    "--last",
    "15m",
    "--predicate",
    'process == "loginwindow" OR eventMessage CONTAINS[c] "authentication" OR eventMessage CONTAINS[c] "login"',
]

MAX_LOG_OUTPUT = 100_000
MAX_EXCERPTS = 10


FAIL_MARKERS = ("fail", "denied", "invalid", "error")
SUCCESS_MARKERS = ("succeeded", "success", "accepted")


def _truncate(value: str, limit: int = 400) -> str:
    return value[:limit] if len(value) > limit else value


def collect_login_events(config: AppConfig, db: Database) -> CollectorResult:
    del config, db

    events: list[EventIn] = []
    try:
        result = subprocess.run(
            LOG_CMD,
            check=False,
            capture_output=True,
            text=True,
            timeout=8,
        )
    except subprocess.TimeoutExpired:
        events.append(
            EventIn(
                source=Source.LOGIN,
                severity=Severity.WARN,
                title="Login collector timeout",
                details={"timeout_seconds": 8},
            )
        )
        return CollectorResult(events=events)
    except Exception as exc:
        events.append(
            EventIn(
                source=Source.LOGIN,
                severity=Severity.WARN,
                title="Login collector execution error",
                details={"error": str(exc)},
            )
        )
        return CollectorResult(events=events)

    stdout = result.stdout[:MAX_LOG_OUTPUT]
    stderr = result.stderr[:MAX_LOG_OUTPUT]

    if result.returncode != 0:
        events.append(
            EventIn(
                source=Source.LOGIN,
                severity=Severity.WARN,
                title="Login collector command failed",
                details={"return_code": result.returncode, "stderr": _truncate(stderr)},
            )
        )
        return CollectorResult(events=events)

    failures: list[str] = []
    successes: list[str] = []
    matched_lines = 0

    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lowered = line.lower()
        if "auth" not in lowered and "login" not in lowered:
            continue
        matched_lines += 1
        if any(marker in lowered for marker in FAIL_MARKERS):
            failures.append(_truncate(line))
        elif any(marker in lowered for marker in SUCCESS_MARKERS):
            successes.append(_truncate(line))

    if failures:
        severity = Severity.HIGH if len(failures) >= 5 else Severity.WARN
        events.append(
            EventIn(
                source=Source.LOGIN,
                severity=severity,
                title="Authentication failures observed",
                details={"count": len(failures), "samples": failures[:MAX_EXCERPTS]},
            )
        )

    if successes:
        events.append(
            EventIn(
                source=Source.LOGIN,
                severity=Severity.INFO,
                title="Authentication successes observed",
                details={"count": len(successes), "samples": successes[:MAX_EXCERPTS]},
            )
        )

    events.append(
        EventIn(
            source=Source.LOGIN,
            severity=Severity.INFO,
            title="Login log scan completed",
            details={"matched_lines": matched_lines},
        )
    )
    return CollectorResult(events=events, metadata={"matched_lines": matched_lines})
