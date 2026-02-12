from __future__ import annotations

from mac_watchdog.insights.schemas import InsightRecord
from mac_watchdog.services.insight_service import InsightService


class ActionQueueService:
    def __init__(self, insight_service: InsightService) -> None:
        self.insight_service = insight_service

    def top_actions(self, limit: int = 5) -> list[dict[str, str | int]]:
        insights: list[InsightRecord] = self.insight_service.open_priority_actions(limit=limit)
        actions: list[dict[str, str | int]] = []
        for insight in insights:
            actions.append(
                {
                    "title": insight.title,
                    "action": insight.action_text,
                    "severity": insight.severity.value,
                    "confidence": insight.confidence.value,
                    "count": insight.count,
                    "status": insight.status.value,
                    "fingerprint": insight.fingerprint or "",
                }
            )
        return actions
