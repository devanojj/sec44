from __future__ import annotations

from mac_watchdog.insights.baseline import classify_ratio, compute_baseline_deltas, compute_median
from mac_watchdog.insights.schemas import BaselineClassification


def test_compute_median_values() -> None:
    assert compute_median([]) == 0.0
    assert compute_median([1, 5, 3]) == 3.0
    assert compute_median([1, 2, 3, 10]) == 2.5


def test_anomaly_classification_thresholds() -> None:
    assert classify_ratio(1.49) == BaselineClassification.NORMAL
    assert classify_ratio(1.5) == BaselineClassification.ELEVATED
    assert classify_ratio(2.99) == BaselineClassification.ELEVATED
    assert classify_ratio(3.0) == BaselineClassification.ANOMALOUS


def test_compute_baseline_deltas_ratio_text() -> None:
    today = {
        "failed_logins_24h": 9,
        "new_listeners_24h": 3,
        "new_processes_24h": 6,
        "suspicious_exec_path_24h": 2,
    }
    history = [
        {
            "failed_logins_24h": 1,
            "new_listeners_24h": 1,
            "new_processes_24h": 2,
            "suspicious_exec_path_24h": 0,
        }
        for _ in range(14)
    ]
    deltas = compute_baseline_deltas(today, history)
    assert deltas["failed_logins_24h"].ratio == 9.0
    assert deltas["failed_logins_24h"].classification == BaselineClassification.ANOMALOUS
