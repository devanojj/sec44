from __future__ import annotations

from typing import Any

from mac_watchdog.insights.schemas import RiskDriver

SOURCE_CATEGORY = {
    "network": "network_exposure",
    "process": "process_anomaly",
    "login": "auth_anomaly",
    "auth": "auth_anomaly",
    "filewatch": "filewatch_anomaly",
}

CATEGORY_EXPLANATIONS = {
    "network_exposure": "Risk driven by newly exposed listening services.",
    "process_anomaly": "Risk driven by unusual or first-seen process behavior.",
    "auth_anomaly": "Risk driven by abnormal authentication failures.",
    "filewatch_anomaly": "Risk driven by suspicious executable file changes.",
}

CATEGORY_ORDER = (
    "network_exposure",
    "process_anomaly",
    "auth_anomaly",
    "filewatch_anomaly",
)


def _event_score(event: dict[str, Any], weights: dict[str, int]) -> float:
    severity = str(event.get("severity") or "INFO").upper()
    return float(weights.get(severity, 0))


def compute_driver_breakdown(events: list[dict[str, Any]], weights: dict[str, int]) -> list[RiskDriver]:
    raw_scores = {category: 0.0 for category in CATEGORY_ORDER}
    for event in events:
        source = str(event.get("source") or "").lower()
        category = SOURCE_CATEGORY.get(source)
        if not category:
            continue
        raw_scores[category] += _event_score(event, weights)

    total = sum(raw_scores.values())
    drivers: list[RiskDriver] = []
    for category in CATEGORY_ORDER:
        score = raw_scores[category]
        percent = round((100.0 * score / total), 2) if total > 0 else 0.0
        drivers.append(
            RiskDriver(
                category=category,  # type: ignore[arg-type]
                score=round(score, 4),
                percent=percent,
                explanation=CATEGORY_EXPLANATIONS[category],
            )
        )

    drivers.sort(key=lambda item: item.percent, reverse=True)
    return drivers


def top_driver(drivers: list[RiskDriver]) -> RiskDriver | None:
    if not drivers:
        return None
    return drivers[0]
