from __future__ import annotations

import csv
import io
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psutil

from shared.enums import Platform, Severity, Source
from shared.schemas import EventEnvelope


def _is_non_local_bind(ip: str) -> bool:
    stripped = ip.strip().lower()
    return stripped not in {"127.0.0.1", "::1", "localhost", ""}


class ProcessCollector:
    def __init__(
        self,
        platform: Platform,
        deny_process_names: list[str] | None = None,
        unusual_exec_paths: list[str] | None = None,
        max_events: int = 150,
    ) -> None:
        self.platform = platform
        self.deny_process_names = {name.lower() for name in (deny_process_names or [])}
        self.unusual_exec_paths = [path.lower() for path in (unusual_exec_paths or [])]
        self.max_events = max_events

    def collect(self) -> list[EventEnvelope]:
        events: list[EventEnvelope] = []
        for proc in psutil.process_iter(attrs=["pid", "name", "exe", "username"]):
            if len(events) >= self.max_events:
                break
            info = proc.info
            name = str(info.get("name") or "unknown")
            exe = str(info.get("exe") or "")
            username = str(info.get("username") or "unknown")
            severity = Severity.INFO
            if name.lower() in self.deny_process_names:
                severity = Severity.HIGH
            elif exe and any(marker in exe.lower() for marker in self.unusual_exec_paths):
                severity = Severity.WARN

            events.append(
                EventEnvelope(
                    ts=datetime.now(UTC),
                    source=Source.PROCESS,
                    severity=severity,
                    platform=self.platform,
                    title="process_seen",
                    details_json={
                        "process_name": name,
                        "pid": int(info.get("pid") or 0),
                        "exe": exe,
                        "username": username,
                    },
                )
            )
        return events


class NetworkCollector:
    def __init__(self, platform: Platform, max_events: int = 150) -> None:
        self.platform = platform
        self.max_events = max_events

    def collect(self) -> list[EventEnvelope]:
        events: list[EventEnvelope] = []
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError):
            return [
                EventEnvelope(
                    ts=datetime.now(UTC),
                    source=Source.SYSTEM,
                    severity=Severity.WARN,
                    platform=self.platform,
                    title="network_collection_unavailable",
                    details_json={"reason": "insufficient_permissions"},
                )
            ]

        for conn in conns:
            if len(events) >= self.max_events:
                break
            if str(conn.status).upper() != "LISTEN":
                continue
            laddr_ip = str(getattr(conn.laddr, "ip", ""))
            laddr_port = int(getattr(conn.laddr, "port", 0))
            process_name = "unknown"
            if conn.pid:
                try:
                    process_name = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                    process_name = "unknown"

            non_local = _is_non_local_bind(laddr_ip)
            events.append(
                EventEnvelope(
                    ts=datetime.now(UTC),
                    source=Source.NETWORK,
                    severity=Severity.WARN if non_local else Severity.INFO,
                    platform=self.platform,
                    title="listener_seen_non_local" if non_local else "listener_seen",
                    details_json={
                        "ip": laddr_ip,
                        "port": laddr_port,
                        "pid": int(conn.pid or 0),
                        "process_name": process_name,
                        "non_local_bind": non_local,
                    },
                )
            )
        return events


class PersistenceCollector:
    def __init__(self, platform: Platform, max_events: int = 80) -> None:
        self.platform = platform
        self.max_events = max_events

    def _macos_paths(self) -> list[Path]:
        return [
            Path.home() / "Library" / "LaunchAgents",
            Path("/Library/LaunchAgents"),
        ]

    def _windows_paths(self) -> list[Path]:
        appdata = Path(os.getenv("APPDATA", str(Path.home() / "AppData" / "Roaming")))
        program_data = Path(os.getenv("PROGRAMDATA", "C:\\ProgramData"))
        return [
            appdata / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
            program_data / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
        ]

    def collect(self) -> list[EventEnvelope]:
        roots = self._windows_paths() if self.platform == Platform.WINDOWS else self._macos_paths()
        events: list[EventEnvelope] = []
        for root in roots:
            if not root.exists() or not root.is_dir():
                continue
            for path in root.iterdir():
                if len(events) >= self.max_events:
                    return events
                if not path.is_file():
                    continue
                try:
                    stat = path.stat()
                except OSError:
                    continue
                events.append(
                    EventEnvelope(
                        ts=datetime.now(UTC),
                        source=Source.SYSTEM,
                        severity=Severity.INFO,
                        platform=self.platform,
                        title="persistence_artifact_seen",
                        details_json={
                            "path": str(path),
                            "mtime": float(stat.st_mtime),
                            "kind": "startup_entry",
                        },
                    )
                )
        return events


class ScheduledTaskCollector:
    CRONTAB_BIN = "/usr/bin/crontab"
    SCHTASKS_BIN = "C:\\Windows\\System32\\schtasks.exe"

    def __init__(self, platform: Platform, max_events: int = 80) -> None:
        self.platform = platform
        self.max_events = max_events

    def _collect_macos(self) -> list[EventEnvelope]:
        try:
            result = subprocess.run(
                [self.CRONTAB_BIN, "-l"],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired, PermissionError):
            return []
        if result.returncode != 0:
            return []

        events: list[EventEnvelope] = []
        for line in result.stdout.splitlines():
            if len(events) >= self.max_events:
                break
            entry = line.strip()
            if not entry or entry.startswith("#"):
                continue
            events.append(
                EventEnvelope(
                    ts=datetime.now(UTC),
                    source=Source.SYSTEM,
                    severity=Severity.INFO,
                    platform=Platform.MACOS,
                    title="scheduled_task_seen",
                    details_json={"scheduler": "cron", "entry": entry[:256]},
                )
            )
        return events

    def _collect_windows(self) -> list[EventEnvelope]:
        try:
            result = subprocess.run(
                [self.SCHTASKS_BIN, "/Query", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                check=False,
                timeout=8,
            )
        except (OSError, subprocess.TimeoutExpired, PermissionError):
            return []
        if result.returncode != 0:
            return []

        reader = csv.reader(io.StringIO(result.stdout))
        events: list[EventEnvelope] = []
        for row in reader:
            if len(events) >= self.max_events:
                break
            if not row:
                continue
            task_name = str(row[0]).strip() if row else ""
            if not task_name:
                continue
            events.append(
                EventEnvelope(
                    ts=datetime.now(UTC),
                    source=Source.SYSTEM,
                    severity=Severity.INFO,
                    platform=Platform.WINDOWS,
                    title="scheduled_task_seen",
                    details_json={"scheduler": "windows_task_scheduler", "task_name": task_name[:256]},
                )
            )
        return events

    def collect(self) -> list[EventEnvelope]:
        if self.platform == Platform.WINDOWS:
            return self._collect_windows()
        return self._collect_macos()


class FilewatchCollector:
    def __init__(self, platform: Platform, watch_paths: list[str], state_path: Path, max_events: int = 100) -> None:
        self.platform = platform
        self.watch_paths = [Path(path).expanduser() for path in watch_paths]
        self.state_path = state_path
        self.max_events = max_events

    def _load_state(self) -> dict[str, float]:
        if not self.state_path.exists():
            return {}
        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
        if not isinstance(payload, dict):
            return {}
        output: dict[str, float] = {}
        for key, value in payload.items():
            if isinstance(value, (int, float)):
                output[str(key)] = float(value)
        return output

    def _save_state(self, state: dict[str, float]) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(json.dumps(state, ensure_ascii=True, separators=(",", ":")), encoding="utf-8")

    def _iter_files(self) -> dict[str, float]:
        current: dict[str, float] = {}
        for root in self.watch_paths:
            if not root.exists() or not root.is_dir():
                continue
            for path in root.rglob("*"):
                if len(current) >= self.max_events * 5:
                    return current
                if not path.is_file():
                    continue
                try:
                    stat = path.stat()
                except OSError:
                    continue
                current[str(path)] = float(stat.st_mtime)
        return current

    def collect(self) -> list[EventEnvelope]:
        previous = self._load_state()
        current = self._iter_files()
        events: list[EventEnvelope] = []

        for file_path, mtime in current.items():
            if len(events) >= self.max_events:
                break
            prev = previous.get(file_path)
            if prev is None:
                events.append(
                    EventEnvelope(
                        ts=datetime.now(UTC),
                        source=Source.FILEWATCH,
                        severity=Severity.INFO,
                        platform=self.platform,
                        title="filewatch_new_path",
                        details_json={"path": file_path, "mtime": mtime},
                    )
                )
            elif mtime > prev:
                events.append(
                    EventEnvelope(
                        ts=datetime.now(UTC),
                        source=Source.FILEWATCH,
                        severity=Severity.INFO,
                        platform=self.platform,
                        title="filewatch_modified_path",
                        details_json={"path": file_path, "mtime": mtime},
                    )
                )

        self._save_state(current)
        return events
