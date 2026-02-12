from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from statistics import mean
from typing import Any

from mac_watchdog.config import AppConfig
from mac_watchdog.db import Database
from mac_watchdog.insights.baseline import compute_baseline_deltas
from mac_watchdog.insights.brief import compose_daily_brief
from mac_watchdog.insights.deltas import compute_new_resolved
from mac_watchdog.insights.schemas import (
    BaselineClassification,
    DailyBrief,
    DailyDeltaPanel,
    InsightConfidence,
    InsightCreate,
    InsightSeverity,
    InsightSource,
    InsightStatus,
    InsightType,
    PostureTrend,
)
from mac_watchdog.sanitizer import safe_json_dumps
from mac_watchdog.services.action_queue import ActionQueueService
from mac_watchdog.services.insight_service import InsightService
from mac_watchdog.services.metrics_service import MetricsService


@dataclass(slots=True)
class InsightEngineResult:
    date: str
    risk_score: int
    generated_insights: int
    new_risks: int
    resolved_risks: int


class InsightEngine:
    def __init__(self, config: AppConfig, db: Database) -> None:
        self.config = config
        self.db = db
        self.metrics_service = MetricsService(db, config.severity_weights)
        self.insight_service = InsightService(db)
        self.action_queue_service = ActionQueueService(self.insight_service)

    def _signal_action(self, signal: str) -> str:
        mapping = {
            "failed_logins_24h": "Review Authentication Failures and rotate credentials if attempts are unauthorized.",
            "new_listeners_24h": "Inspect new listeners and close unnecessary exposed ports.",
            "new_processes_24h": "Validate first-seen processes against expected software inventory.",
            "suspicious_exec_path_24h": "Quarantine binaries from temp or download paths pending validation.",
        }
        return mapping.get(signal, "Investigate this anomaly against recent system changes.")

    def _signal_source(self, signal: str) -> InsightSource:
        if signal == "failed_logins_24h":
            return InsightSource.AUTH
        if signal == "new_listeners_24h":
            return InsightSource.NETWORK
        if signal in {"new_processes_24h", "suspicious_exec_path_24h"}:
            return InsightSource.PROCESS
        return InsightSource.SYSTEM

    def _signal_confidence(self, signal: str, classification: BaselineClassification, today: int) -> InsightConfidence:
        if classification == BaselineClassification.ANOMALOUS:
            if signal in {"new_listeners_24h", "suspicious_exec_path_24h"} and today > 0:
                return InsightConfidence.HIGH
            return InsightConfidence.MEDIUM
        if classification == BaselineClassification.ELEVATED:
            return InsightConfidence.LOW
        return InsightConfidence.LOW

    def _source_for_event(self, source: str) -> InsightSource:
        normalized = source.lower()
        if normalized == "login":
            return InsightSource.AUTH
        if normalized == "network":
            return InsightSource.NETWORK
        if normalized == "process":
            return InsightSource.PROCESS
        if normalized == "filewatch":
            return InsightSource.FILEWATCH
        return InsightSource.SYSTEM

    def _compute_posture_trend(self, risk_score: int, high_count: int, recent_metrics: list[Any]) -> PostureTrend:
        risk_values = [metric.risk_score for metric in recent_metrics]
        high_values = [metric.high_count for metric in recent_metrics]

        avg_risk = mean(risk_values) if risk_values else float(risk_score)
        avg_high = mean(high_values) if high_values else float(high_count)

        if risk_score <= avg_risk * 0.9 and high_count <= avg_high * 0.9:
            status = "Improving"
        elif risk_score >= avg_risk * 1.1 or high_count >= avg_high * 1.1:
            status = "Regressing"
        else:
            status = "Stable"

        return PostureTrend(
            risk_score_today=risk_score,
            risk_score_7d_avg=round(avg_risk, 2),
            high_alerts_today=high_count,
            high_alerts_7d_avg=round(avg_high, 2),
            status=status,
            high_alert_series_7d=high_values[-7:],
        )

    def _record_baseline_insights(
        self,
        ts: str,
        baseline_deltas: dict[str, Any],
    ) -> list[InsightCreate]:
        insights: list[InsightCreate] = []
        for signal, delta in baseline_deltas.items():
            if not hasattr(delta, "classification"):
                continue
            if delta.classification == BaselineClassification.NORMAL:
                continue
            severity = InsightSeverity.WARN
            if delta.classification == BaselineClassification.ANOMALOUS:
                severity = InsightSeverity.HIGH

            insight = InsightCreate(
                ts=ts,
                insight_type=InsightType.ANOMALY,
                source=self._signal_source(signal),
                severity=severity,
                confidence=self._signal_confidence(signal, delta.classification, delta.today),
                title=f"{signal} is {delta.ratio:.1f}x above baseline",
                explanation=(
                    "Rule: classify normal when ratio < 1.5, elevated when 1.5 <= ratio < 3, "
                    f"anomalous when ratio >= 3. Observed today={delta.today}, "
                    f"baseline={delta.baseline:.2f}, ratio={delta.ratio:.2f}."
                ),
                evidence={
                    "signal": signal,
                    "today": delta.today,
                    "baseline": delta.baseline,
                    "ratio": delta.ratio,
                    "classification": delta.classification.value,
                },
                action_text=self._signal_action(signal),
            )
            insights.append(insight)
        return insights

    def _record_driver_insights(self, ts: str, drivers: list[Any], risk_score: int) -> list[InsightCreate]:
        out: list[InsightCreate] = []
        for driver in drivers[:2]:
            if driver.percent <= 0:
                continue
            severity = InsightSeverity.INFO
            if driver.percent >= 35:
                severity = InsightSeverity.WARN
            if driver.percent >= 50 and risk_score >= 60:
                severity = InsightSeverity.HIGH

            source = InsightSource.SYSTEM
            if driver.category == "network_exposure":
                source = InsightSource.NETWORK
            elif driver.category == "process_anomaly":
                source = InsightSource.PROCESS
            elif driver.category == "auth_anomaly":
                source = InsightSource.AUTH
            elif driver.category == "filewatch_anomaly":
                source = InsightSource.FILEWATCH

            out.append(
                InsightCreate(
                    ts=ts,
                    insight_type=InsightType.DRIVER,
                    source=source,
                    severity=severity,
                    confidence=InsightConfidence.MEDIUM,
                    title=f"Risk driver: {driver.category} ({driver.percent:.1f}%)",
                    explanation=(
                        "Rule: driver share is category_weighted_score / total_weighted_score for today. "
                        f"Category score={driver.score:.2f}, share={driver.percent:.2f}%."
                    ),
                    evidence={
                        "category": driver.category,
                        "percent": driver.percent,
                        "score": driver.score,
                    },
                    action_text=driver.explanation,
                )
            )
        return out

    def _record_delta_insights(
        self,
        ts: str,
        new_risks: list[dict[str, Any]],
        resolved_risks: list[dict[str, Any]],
    ) -> list[InsightCreate]:
        insights: list[InsightCreate] = []
        for record in new_risks:
            severity = InsightSeverity(str(record.get("severity") or "WARN"))
            source = self._source_for_event(str(record.get("source") or "system"))
            insights.append(
                InsightCreate(
                    ts=ts,
                    insight_type=InsightType.CHANGE,
                    source=source,
                    severity=severity,
                    confidence=InsightConfidence.HIGH if severity == InsightSeverity.HIGH else InsightConfidence.MEDIUM,
                    title=f"New risk introduced: {record.get('title')}",
                    explanation=(
                        "Rule: risk marked new when its fingerprint exists in today's WARN/HIGH set "
                        "and did not exist in yesterday's WARN/HIGH set."
                    ),
                    evidence=record,
                    action_text="Review evidence and remediate immediately if exposure is not expected.",
                    fingerprint=str(record.get("fingerprint")),
                )
            )

        for record in resolved_risks:
            source = self._source_for_event(str(record.get("source") or "system"))
            insights.append(
                InsightCreate(
                    ts=ts,
                    insight_type=InsightType.CHANGE,
                    source=source,
                    severity=InsightSeverity.INFO,
                    confidence=InsightConfidence.MEDIUM,
                    title=f"Risk resolved since yesterday: {record.get('title')}",
                    explanation=(
                        "Rule: risk marked resolved when its fingerprint existed in yesterday's WARN/HIGH set "
                        "and is absent from today's WARN/HIGH set."
                    ),
                    evidence=record,
                    action_text="Confirm the issue remains resolved on the next cycle.",
                    fingerprint=str(record.get("fingerprint")),
                    status=InsightStatus.RESOLVED,
                )
            )

        return insights

    def generate_cycle(self, now: datetime | None = None) -> InsightEngineResult:
        current = now or datetime.now(UTC)
        current_date = current.date()
        day = current_date.isoformat()
        ts = current.isoformat()

        today_events = self.metrics_service.events_for_day(current_date)
        yesterday_events = self.metrics_service.events_for_day(current_date - timedelta(days=1))

        signal_counts = self.metrics_service._signal_counts(today_events)
        prior = self.metrics_service.prior_signal_history(current_date, days=14)
        baseline_deltas = compute_baseline_deltas(signal_counts, prior)

        metric = self.metrics_service.build_and_store_metrics(
            current_date,
            today_events,
            {key: value.model_dump() for key, value in baseline_deltas.items()},
        )

        new_risks, resolved_risks, active_fingerprints = compute_new_resolved(today_events, yesterday_events)

        generated: list[InsightCreate] = []
        generated.extend(self._record_baseline_insights(ts, baseline_deltas))
        generated.extend(self._record_driver_insights(ts, metric.drivers, metric.risk_score))
        generated.extend(self._record_delta_insights(ts, new_risks, resolved_risks))

        recent_metrics = self.metrics_service.list_recent_metrics(7, end_date=current_date)
        trend = self._compute_posture_trend(metric.risk_score, metric.high_count, recent_metrics)
        generated.append(
            InsightCreate(
                ts=ts,
                insight_type=InsightType.POSTURE,
                source=InsightSource.SYSTEM,
                severity=InsightSeverity.WARN if trend.status == "Regressing" else InsightSeverity.INFO,
                confidence=InsightConfidence.MEDIUM,
                title=f"Posture trend: {trend.status}",
                explanation=(
                    "Rule: Improving when both risk score and HIGH alerts are <= 90% of 7d average; "
                    "Regressing when either is >= 110%; else Stable."
                ),
                evidence=trend.model_dump(),
                action_text="Prioritize HIGH-confidence open items if posture is regressing.",
            )
        )

        persisted = self.insight_service.bulk_record(generated)
        self.insight_service.resolve_absent_change_insights(active_fingerprints, ts)

        action_queue = self.action_queue_service.top_actions(limit=5)
        brief = compose_daily_brief(
            date_value=day,
            risk_score=metric.risk_score,
            recent_risk_scores=[item.risk_score for item in recent_metrics[-7:]],
            drivers=metric.drivers,
            baseline_deltas=baseline_deltas,
            action_texts=[str(item["action"]) for item in action_queue],
            extra_titles=[str(item.get("title") or "") for item in new_risks],
        )

        panel = DailyDeltaPanel(new_risks=new_risks[:10], resolved_risks=resolved_risks[:10])
        self.db.set_app_state(f"daily_brief:{day}", safe_json_dumps(brief.model_dump()))
        self.db.set_app_state("daily_brief_latest", safe_json_dumps(brief.model_dump()))
        self.db.set_app_state(f"daily_delta:{day}", safe_json_dumps(panel.model_dump()))

        return InsightEngineResult(
            date=day,
            risk_score=metric.risk_score,
            generated_insights=len(persisted),
            new_risks=len(new_risks),
            resolved_risks=len(resolved_risks),
        )

    def run_backfill(self) -> dict[str, int]:
        metric_count = self.metrics_service.backfill_daily_metrics()
        insight_count = self.insight_service.backfill_from_events()
        return {"daily_metrics_backfilled": metric_count, "insights_backfilled": insight_count}
