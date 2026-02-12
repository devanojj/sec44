from __future__ import annotations

from mac_watchdog.insights.drivers import compute_driver_breakdown


def test_driver_percentages_sum_to_approximately_100() -> None:
    events = [
        {"source": "network", "severity": "HIGH"},
        {"source": "process", "severity": "WARN"},
        {"source": "login", "severity": "WARN"},
        {"source": "filewatch", "severity": "INFO"},
    ]
    weights = {"INFO": 1, "WARN": 3, "HIGH": 8}
    drivers = compute_driver_breakdown(events, weights)

    total_percent = sum(driver.percent for driver in drivers)
    assert 99.0 <= total_percent <= 101.0
    assert drivers[0].category == "network_exposure"
