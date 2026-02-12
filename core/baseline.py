from __future__ import annotations

from statistics import median

from core.models import BaselineClassification, BaselineMetric


METRIC_KEYS = (
    "failed_logins",
    "new_listeners",
    "new_processes",
    "suspicious_execs",
)


def compute_median(values: list[int]) -> float:
    if not values:
        return 0.0
    return float(median(values))


def classify_ratio(ratio: float) -> BaselineClassification:
    if ratio < 1.5:
        return BaselineClassification.NORMAL
    if ratio < 3.0:
        return BaselineClassification.ELEVATED
    return BaselineClassification.ANOMALOUS


def compute_baseline(
    today_metrics: dict[str, int],
    prior_metrics: list[dict[str, int]],
) -> dict[str, BaselineMetric]:
    output: dict[str, BaselineMetric] = {}
    for key in METRIC_KEYS:
        today = int(today_metrics.get(key, 0))
        history = [int(day.get(key, 0)) for day in prior_metrics]
        baseline = compute_median(history)
        ratio = today / max(1.0, baseline)
        output[key] = BaselineMetric(
            metric=key,
            today=today,
            baseline=baseline,
            ratio=round(ratio, 4),
            classification=classify_ratio(ratio),
        )
    return output
