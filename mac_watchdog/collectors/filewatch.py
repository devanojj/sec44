from __future__ import annotations

import os
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any

from mac_watchdog.config import AppConfig
from mac_watchdog.models import EventIn, Severity, Source

try:
    from watchdog.events import FileSystemEvent, FileSystemEventHandler
    from watchdog.observers import Observer
except Exception:  # pragma: no cover - optional dependency import guard
    FileSystemEvent = Any  # type: ignore[assignment]
    FileSystemEventHandler = object  # type: ignore[assignment]
    Observer = None


EXEC_EXTENSIONS = {".app", ".pkg", ".dmg"}


def _is_home_subpath(path: Path) -> bool:
    home = Path.home().resolve()
    try:
        common = Path(os.path.commonpath([str(home), str(path.resolve(strict=False))]))
    except ValueError:
        return False
    return common == home


class _DebouncedHandler(FileSystemEventHandler):  # type: ignore[misc]
    def __init__(self, queue: deque[dict[str, Any]], debounce_seconds: float = 2.0) -> None:
        self.queue = queue
        self.debounce_seconds = debounce_seconds
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def on_any_event(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        event_type = getattr(event, "event_type", "unknown")
        src_path = str(getattr(event, "src_path", ""))
        dest_path = str(getattr(event, "dest_path", ""))
        key = f"{event_type}:{src_path}:{dest_path}"

        now = time.time()
        with self._lock:
            last = self._seen.get(key)
            if last is not None and (now - last) < self.debounce_seconds:
                return
            self._seen[key] = now

        payload = {
            "event_type": event_type,
            "src_path": src_path,
            "dest_path": dest_path,
            "ts": time.time(),
        }
        self.queue.append(payload)


class FileWatchService:
    def __init__(self, config: AppConfig) -> None:
        self._queue: deque[dict[str, Any]] = deque()
        self._observer: Any = None
        self._paths: list[Path] = [Path(item).expanduser().resolve(strict=False) for item in config.watch_paths]
        self._handler = _DebouncedHandler(self._queue)
        self._started = False

    def start(self) -> None:
        if Observer is None:
            raise RuntimeError("watchdog is not available")
        if self._started:
            return

        observer = Observer()
        for path in self._paths:
            if not path.exists() or not path.is_dir():
                continue
            if path.is_symlink():
                continue
            if not _is_home_subpath(path):
                continue
            observer.schedule(self._handler, str(path), recursive=False)

        observer.daemon = True
        observer.start()
        self._observer = observer
        self._started = True

    def stop(self) -> None:
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=5)
        self._observer = None
        self._started = False

    def drain_events(self) -> list[EventIn]:
        out: list[EventIn] = []
        while self._queue:
            item = self._queue.popleft()
            path_str = item.get("dest_path") or item.get("src_path") or ""
            path = Path(path_str)
            severity = Severity.INFO
            title = "File change detected"

            if path.suffix.lower() in EXEC_EXTENSIONS and "Downloads" in path_str:
                severity = Severity.WARN
                title = "Installer artifact detected in Downloads"

            if path.exists():
                try:
                    mode = path.stat().st_mode
                    if mode & 0o111:
                        severity = Severity.HIGH
                        title = "Executable file change detected"
                except OSError:
                    pass

            out.append(
                EventIn(
                    source=Source.FILEWATCH,
                    severity=severity,
                    title=title,
                    details=item,
                )
            )

        return out
