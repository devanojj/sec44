from __future__ import annotations

from mac_watchdog.insights.brief import compose_daily_brief
from mac_watchdog.insights.schemas import BaselineClassification, BaselineDelta, RiskDriver


def test_daily_brief_contains_required_fields() -> None:
    deltas = {
        "failed_logins_24h": BaselineDelta(
            signal="failed_logins_24h",
            today=8,
            baseline=2.0,
            ratio=4.0,
            classification=BaselineClassification.ANOMALOUS,
        ),
        "new_listeners_24h": BaselineDelta(
            signal="new_listeners_24h",
            today=3,
            baseline=1.0,
            ratio=3.0,
            classification=BaselineClassification.ANOMALOUS,
        ),
        "new_processes_24h": BaselineDelta(
            signal="new_processes_24h",
            today=2,
            baseline=2.0,
            ratio=1.0,
            classification=BaselineClassification.NORMAL,
        ),
        "suspicious_exec_path_24h": BaselineDelta(
            signal="suspicious_exec_path_24h",
            today=1,
            baseline=0.0,
            ratio=1.0,
            classification=BaselineClassification.NORMAL,
        ),
    }
    drivers = [
        RiskDriver(
            category="network_exposure",
            score=11.0,
            percent=55.0,
            explanation="Risk driven by newly exposed listening services.",
        )
    ]

    brief = compose_daily_brief(
        date_value="2026-02-12",
        risk_score=80,
        recent_risk_scores=[40, 50, 60, 70, 80, 90, 80],
        drivers=drivers,
        baseline_deltas=deltas,
        action_texts=["Close port 6666", "Rotate affected credentials"],
        extra_titles=["New risk introduced: New external listener"],
    )

    assert brief.risk_score == 80
    assert brief.top_risk_driver == "network exposure"
    assert len(brief.unusual_behaviors) >= 2
    assert len(brief.priority_actions) == 2
