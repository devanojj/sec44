from __future__ import annotations

import argparse
from datetime import UTC, datetime, time, timedelta
from pathlib import Path

from mac_watchdog.config import DEFAULT_CONFIG_PATH, ensure_app_paths, load_config
from mac_watchdog.db import Database
from mac_watchdog.insights import InsightEngine
from mac_watchdog.models import EventIn, Severity, Source


def _ts_for_day(day: datetime, hour: int, minute: int) -> str:
    return day.replace(hour=hour, minute=minute, second=0, microsecond=0).isoformat()


def _build_day_events(day: datetime, day_index: int, total_days: int) -> list[EventIn]:
    events: list[EventIn] = []
    is_today = day_index == total_days - 1
    is_yesterday = day_index == total_days - 2

    login_failures = 1
    new_listeners = 1 if day_index % 3 == 0 else 0
    new_processes = 2
    suspicious_execs = 0

    if is_today:
        login_failures = 9
        new_listeners = 4
        new_processes = 8
        suspicious_execs = 3
    elif is_yesterday:
        login_failures = 4
        new_listeners = 2
        new_processes = 5
        suspicious_execs = 1

    if login_failures:
        events.append(
            EventIn(
                ts=_ts_for_day(day, 8, 15),
                source=Source.LOGIN,
                severity=Severity.HIGH if login_failures >= 5 else Severity.WARN,
                title="Authentication failures observed",
                details={"count": login_failures, "samples": [f"demo auth fail burst {day_index}"]},
            )
        )

    for i in range(new_listeners):
        if is_yesterday and i == 0:
            ip = "0.0.0.0"
            port = 5555
        elif is_today and i == 0:
            ip = "0.0.0.0"
            port = 6666
        else:
            ip = "127.0.0.1"
            port = 7000 + i

        title = "New external listener on all interfaces" if ip == "0.0.0.0" else "New localhost listener detected"
        severity = Severity.HIGH if ip == "0.0.0.0" else Severity.WARN
        events.append(
            EventIn(
                ts=_ts_for_day(day, 9, min(59, 5 + i)),
                source=Source.NETWORK,
                severity=severity,
                title=title,
                details={
                    "ip": ip,
                    "port": port,
                    "family": "AF_INET",
                    "pid": 200 + i,
                    "process_name": "demo_service",
                },
            )
        )

    for i in range(new_processes):
        events.append(
            EventIn(
                ts=_ts_for_day(day, 10, min(59, 2 + i)),
                source=Source.PROCESS,
                severity=Severity.WARN,
                title="New process observed",
                details={
                    "pid": 400 + i,
                    "name": f"demo-proc-{i}",
                    "username": "demo",
                    "exe": f"/Applications/Demo{(i % 3) + 1}.app/Contents/MacOS/demo",
                },
            )
        )

    for i in range(suspicious_execs):
        events.append(
            EventIn(
                ts=_ts_for_day(day, 11, min(59, 10 + i)),
                source=Source.PROCESS,
                severity=Severity.HIGH,
                title="Process running from unusual path",
                details={
                    "pid": 900 + i,
                    "name": f"suspicious-{i}",
                    "exe": f"/private/tmp/suspicious_{day_index}_{i}",
                    "username": "demo",
                },
            )
        )

    if is_today:
        events.append(
            EventIn(
                ts=_ts_for_day(day, 13, 5),
                source=Source.FILEWATCH,
                severity=Severity.HIGH,
                title="Executable file change detected",
                details={
                    "event_type": "modified",
                    "src_path": "/Users/demo/Downloads/suspicious_installer.pkg",
                    "dest_path": "",
                },
            )
        )

    events.append(
        EventIn(
            ts=_ts_for_day(day, 23, 55),
            source=Source.SYSTEM,
            severity=Severity.INFO,
            title="Seeded demo collection cycle",
            details={"day_index": day_index},
        )
    )
    return events


def seed_demo_data(config_path: Path, reset: bool, days: int) -> None:
    ensure_app_paths(config_path)
    config = load_config(config_path)
    db = Database(config.db_path)
    engine = InsightEngine(config=config, db=db)

    try:
        if reset:
            db.execute("DELETE FROM events")
            db.execute("DELETE FROM process_seen")
            db.execute("DELETE FROM latest_snapshots")
            db.execute("DELETE FROM app_state")
            db.execute("DELETE FROM daily_metrics")
            db.execute("DELETE FROM insights")

        now = datetime.now(UTC)
        start_day = datetime.combine((now.date() - timedelta(days=days - 1)), time.min, tzinfo=UTC)

        all_events: list[EventIn] = []
        for i in range(days):
            day = start_day + timedelta(days=i)
            all_events.extend(_build_day_events(day, i, days))

        db.insert_events(all_events)
        backfill = engine.run_backfill()
        summary = engine.generate_cycle(now=now)

        print("Seed complete")
        print(f"Database: {config.db_path}")
        print(f"Events inserted: {len(all_events)}")
        print(f"Backfill: {backfill}")
        print(f"Insight cycle: {summary}")
    finally:
        db.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed deterministic demo data for Mac Security Watchdog")
    parser.add_argument("--config", type=str, default=None, help="Path to config.toml")
    parser.add_argument("--days", type=int, default=15, help="Number of days to seed")
    parser.add_argument("--no-reset", action="store_true", help="Append to existing data instead of resetting")
    args = parser.parse_args()

    config_path = Path(args.config).expanduser() if args.config else DEFAULT_CONFIG_PATH
    seed_demo_data(config_path=config_path, reset=not args.no_reset, days=max(2, args.days))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
