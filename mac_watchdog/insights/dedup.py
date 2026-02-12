from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any

NORMALIZE_RE = re.compile(r"\s+")
STABLE_KEYS = (
    "ip",
    "port",
    "process_name",
    "pid",
    "name",
    "exe",
    "username",
    "src_path",
    "dest_path",
    "event_type",
    "sample",
    "signal",
    "classification",
)


def normalize_title(title: str) -> str:
    lowered = title.strip().lower()
    return NORMALIZE_RE.sub(" ", lowered)


def stable_evidence_slice(evidence: dict[str, Any]) -> dict[str, Any]:
    stable: dict[str, Any] = {}
    for key in STABLE_KEYS:
        if key in evidence:
            stable[key] = evidence[key]
    if not stable:
        for key in sorted(evidence.keys()):
            value = evidence[key]
            if isinstance(value, (str, int, float, bool)) or value is None:
                stable[key] = value
    return stable


def build_fingerprint(source: str, title: str, evidence: dict[str, Any]) -> str:
    payload = {
        "source": source.strip().lower(),
        "title": normalize_title(title),
        "stable": stable_evidence_slice(evidence),
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def within_window(last_seen: str, now_ts: str, window_minutes: int) -> bool:
    if window_minutes <= 0:
        return False
    try:
        last = datetime.fromisoformat(last_seen)
        now = datetime.fromisoformat(now_ts)
    except ValueError:
        return False
    if last.tzinfo is None:
        last = last.replace(tzinfo=UTC)
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    return (now - last) <= timedelta(minutes=window_minutes)
