from __future__ import annotations

from statistics import median

from mac_watchdog.insights.schemas import BaselineClassification, BaselineDelta

SIGNAL_KEYS = (
    "failed_logins_24h",
    "new_listeners_24h",
    "new_processes_24h",
    "suspicious_exec_path_24h",
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


def compute_baseline_deltas(
    today_signals: dict[str, int],
    prior_days: list[dict[str, int]],
) -> dict[str, BaselineDelta]:
    output: dict[str, BaselineDelta] = {}
    for signal in SIGNAL_KEYS:
        today_value = int(today_signals.get(signal, 0))
        history = [int(day.get(signal, 0)) for day in prior_days]
        baseline_value = compute_median(history)
        ratio = today_value / max(1.0, baseline_value)
        output[signal] = BaselineDelta(
            signal=signal,  # type: ignore[arg-type]
            today=today_value,
            baseline=baseline_value,
            ratio=round(ratio, 4),
            classification=classify_ratio(ratio),
        )
    return output
