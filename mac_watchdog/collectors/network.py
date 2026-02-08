from __future__ import annotations

import socket
from datetime import UTC, datetime
from typing import Any

import psutil

from mac_watchdog.config import AppConfig
from mac_watchdog.db import Database
from mac_watchdog.models import CollectorResult, EventIn, Severity, Source

SNAPSHOT_KEY = "network_listeners"


def _listener_key(item: dict[str, Any]) -> str:
    return f"{item['ip']}:{item['port']}:{item.get('process_name') or ''}:{item.get('pid') or ''}"


def _family_name(value: Any) -> str:
    if value == socket.AF_INET:
        return "AF_INET"
    if value == socket.AF_INET6:
        return "AF_INET6"
    return str(value)


def collect_network_events(config: AppConfig, db: Database) -> CollectorResult:
    events: list[EventIn] = []
    listeners: list[dict[str, Any]] = []

    try:
        conns = psutil.net_connections(kind="inet")
    except Exception as exc:
        events.append(
            EventIn(
                source=Source.NETWORK,
                severity=Severity.WARN,
                title="Network collector failed",
                details={"error": str(exc)},
            )
        )
        return CollectorResult(events=events)

    for conn in conns:
        status = getattr(conn, "status", "")
        if status != psutil.CONN_LISTEN and status != "LISTEN":
            continue

        laddr = getattr(conn, "laddr", None)
        if not laddr:
            continue

        ip = getattr(laddr, "ip", None)
        port = getattr(laddr, "port", None)
        if ip is None or port is None:
            if isinstance(laddr, tuple) and len(laddr) >= 2:
                ip = str(laddr[0])
                port = int(laddr[1])
            else:
                continue

        pid = getattr(conn, "pid", None)
        process_name: str | None = None
        if pid is not None:
            try:
                process_name = psutil.Process(pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                process_name = None
            except Exception:
                process_name = None

        listeners.append(
            {
                "ip": str(ip),
                "port": int(port),
                "family": _family_name(getattr(conn, "family", "unknown")),
                "pid": pid,
                "process_name": process_name,
            }
        )

    listeners.sort(key=lambda item: (item["ip"], item["port"], item.get("process_name") or ""))

    previous_snapshot = db.get_latest_snapshot(SNAPSHOT_KEY)
    previous_items = previous_snapshot["blob"] if previous_snapshot else []
    prev_keys = {_listener_key(item) for item in previous_items if isinstance(item, dict)}

    new_listeners: list[dict[str, Any]] = []
    deny_names = [name.lower() for name in config.deny_process_names]

    for listener in listeners:
        key = _listener_key(listener)
        if key in prev_keys:
            continue
        new_listeners.append(listener)

        ip = listener["ip"]
        pname = (listener.get("process_name") or "").lower()
        if any(deny in pname for deny in deny_names):
            severity = Severity.HIGH
            title = "Denylisted process opened listener"
        elif ip in {"0.0.0.0", "::"}:
            severity = Severity.HIGH
            title = "New external listener on all interfaces"
        elif ip in {"127.0.0.1", "::1", "localhost"}:
            severity = Severity.WARN
            title = "New localhost listener detected"
        else:
            severity = Severity.HIGH
            title = "New listener on non-loopback interface"

        events.append(
            EventIn(
                source=Source.NETWORK,
                severity=severity,
                title=title,
                details=listener,
            )
        )

    db.set_latest_snapshot(SNAPSHOT_KEY, listeners, datetime.now(UTC).isoformat())
    events.append(
        EventIn(
            source=Source.NETWORK,
            severity=Severity.INFO,
            title="Network listener snapshot completed",
            details={"listener_count": len(listeners), "new_listeners": len(new_listeners)},
        )
    )

    return CollectorResult(
        events=events,
        metadata={"listener_count": len(listeners), "new_listener_count": len(new_listeners)},
    )
