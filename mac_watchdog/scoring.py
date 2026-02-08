from __future__ import annotations

from datetime import UTC, datetime


def calculate_score_from_counts(counts: dict[str, int], weights: dict[str, int]) -> int:
    return sum(counts.get(level, 0) * weights.get(level, 0) for level in ("INFO", "WARN", "HIGH"))


def classify_score(score: int) -> str:
    if score >= 80:
        return "HIGH"
    if score >= 25:
        return "WARN"
    return "INFO"


def utc_day_start_iso(now: datetime | None = None) -> str:
    current = now or datetime.now(UTC)
    start = current.astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    return start.isoformat()
