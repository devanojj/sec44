from __future__ import annotations

from statistics import mean

from mac_watchdog.insights.schemas import BaselineClassification, BaselineDelta, DailyBrief, RiskDriver


def _driver_label(driver: RiskDriver | None) -> str:
    if driver is None:
        return "No dominant driver"
    return driver.category.replace("_", " ")


def _build_unusual_behaviors(
    baseline_deltas: dict[str, BaselineDelta],
    extra_titles: list[str],
) -> list[str]:
    out: list[str] = []
    for key in (
        "failed_logins_24h",
        "new_listeners_24h",
        "new_processes_24h",
        "suspicious_exec_path_24h",
    ):
        delta = baseline_deltas[key]
        if delta.classification == BaselineClassification.NORMAL:
            continue
        out.append(f"{key}: {delta.ratio:.1f}x above baseline")

    for title in extra_titles:
        if len(out) >= 4:
            break
        if title not in out:
            out.append(title)

    return out[:4]


def compose_daily_brief(
    date_value: str,
    risk_score: int,
    recent_risk_scores: list[int],
    drivers: list[RiskDriver],
    baseline_deltas: dict[str, BaselineDelta],
    action_texts: list[str],
    extra_titles: list[str],
) -> DailyBrief:
    avg_7d = mean(recent_risk_scores) if recent_risk_scores else 0.0
    delta = round(risk_score - avg_7d, 2)
    driver = drivers[0] if drivers else None

    unusual_behaviors = _build_unusual_behaviors(baseline_deltas, extra_titles)
    priority_actions = [item for item in action_texts if item][:5]

    return DailyBrief(
        date=date_value,
        risk_score=risk_score,
        delta_vs_7d_avg=delta,
        top_risk_driver=_driver_label(driver),
        unusual_behaviors=unusual_behaviors,
        priority_actions=priority_actions[:3],
    )
