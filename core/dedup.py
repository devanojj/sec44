from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
from typing import Any

from core.models import Insight

STABLE_EVIDENCE_KEYS = (
    "process_name",
    "exe",
    "pid",
    "ip",
    "port",
    "username",
    "event_type",
    "listener",
    "metric",
    "classification",
    "change",
)


def build_fingerprint(source: str, title: str, evidence: dict[str, Any]) -> str:
    stable: dict[str, Any] = {}
    for key in STABLE_EVIDENCE_KEYS:
        if key in evidence:
            stable[key] = evidence[key]
    if not stable:
        for key, value in sorted(evidence.items()):
            if isinstance(value, (str, int, float, bool)) or value is None:
                stable[key] = value
    payload = {
        "source": source.lower(),
        "title": " ".join(title.lower().split()),
        "stable": stable,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def suppress_repeated(
    candidates: list[Insight],
    recent_last_seen: dict[str, datetime],
    now: datetime,
    window_minutes: int = 30,
) -> tuple[list[Insight], list[str]]:
    accepted: list[Insight] = []
    suppressed: list[str] = []
    window = timedelta(minutes=window_minutes)
    for insight in candidates:
        last = recent_last_seen.get(insight.fingerprint)
        if last is not None and (now - last) <= window:
            suppressed.append(insight.fingerprint)
            continue
        accepted.append(insight)
    return accepted, suppressed
