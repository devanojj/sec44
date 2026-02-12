from __future__ import annotations

from collections import defaultdict
from datetime import UTC, date, datetime, timedelta
from statistics import mean
from typing import Any

from core.baseline import METRIC_KEYS, compute_baseline
from core.dedup import build_fingerprint
from core.models import DailyBrief, DriverShare, Insight, InsightBundle
from shared.enums import Severity, Source


def _safe_ts(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed.astimezone(UTC) if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _category_for_source(source: str) -> str:
    lookup = {
        Source.NETWORK.value: "network_exposure",
        Source.PROCESS.value: "process",
        Source.AUTH.value: "auth",
        Source.FILEWATCH.value: "filewatch",
    }
    return lookup.get(source, "process")


def _listener_key(event: dict[str, Any]) -> str | None:
    details = event.get("details_json") or {}
    if not isinstance(details, dict):
        return None
    ip = str(details.get("ip") or details.get("laddr_ip") or "")
    port = details.get("port") or details.get("laddr_port")
    if port is None:
        return None
    return f"{ip}:{port}"


def _process_key(event: dict[str, Any]) -> str | None:
    details = event.get("details_json") or {}
    if not isinstance(details, dict):
        return None
    name = str(details.get("process_name") or details.get("name") or "")
    exe = str(details.get("exe") or "")
    if not name and not exe:
        return None
    return f"{name}|{exe}"


def _is_failed_login(event: dict[str, Any]) -> bool:
    source = str(event.get("source") or "")
    if source != Source.AUTH.value:
        return False
    title = str(event.get("title") or "").lower()
    if "failed" in title:
        return True
    details = event.get("details_json") or {}
    if isinstance(details, dict) and str(details.get("event_type") or "").lower() == "failed_login":
        return True
    severity = str(event.get("severity") or "")
    return severity in {Severity.WARN.value, Severity.HIGH.value}


def _is_suspicious_exec(event: dict[str, Any]) -> bool:
    if str(event.get("source") or "") != Source.PROCESS.value:
        return False
    details = event.get("details_json") or {}
    if not isinstance(details, dict):
        return False
    exe = str(details.get("exe") or "").lower()
    markers = ["/tmp/", "/private/tmp/", "\\appdata\\local\\temp\\", "\\temp\\"]
    return any(marker in exe for marker in markers)


def _event_fingerprint(event: dict[str, Any]) -> str:
    source = str(event.get("source") or Source.SYSTEM.value)
    title = str(event.get("title") or "event")
    details = event.get("details_json") if isinstance(event.get("details_json"), dict) else {}
    return build_fingerprint(source, title, details)


def _daily_sets(events: list[dict[str, Any]]) -> tuple[set[str], set[str]]:
    listeners: set[str] = set()
    processes: set[str] = set()
    for event in events:
        listener = _listener_key(event)
        process = _process_key(event)
        if listener:
            listeners.add(listener)
        if process:
            processes.add(process)
    return listeners, processes


def _compute_day_metrics(
    grouped: dict[date, list[dict[str, Any]]],
    target_day: date,
) -> dict[str, int]:
    today_events = grouped.get(target_day, [])
    prev_day = target_day - timedelta(days=1)
    prev_events = grouped.get(prev_day, [])
    today_listeners, today_processes = _daily_sets(today_events)
    prev_listeners, prev_processes = _daily_sets(prev_events)

    return {
        "failed_logins": sum(1 for event in today_events if _is_failed_login(event)),
        "new_listeners": len(today_listeners - prev_listeners),
        "new_processes": len(today_processes - prev_processes),
        "suspicious_execs": sum(1 for event in today_events if _is_suspicious_exec(event)),
    }


def _driver_shares(events: list[dict[str, Any]], severity_weights: dict[str, int]) -> list[DriverShare]:
    raw_scores: dict[str, float] = defaultdict(float)
    for event in events:
        source = str(event.get("source") or Source.SYSTEM.value)
        severity = str(event.get("severity") or Severity.INFO.value)
        category = _category_for_source(source)
        raw_scores[category] += float(severity_weights.get(severity, 0))

    total = sum(raw_scores.values())
    if total <= 0:
        return []

    output: list[DriverShare] = []
    for category, score in sorted(raw_scores.items(), key=lambda item: item[1], reverse=True):
        output.append(
            DriverShare(
                category=category,
                score=round(score, 3),
                percent=round((score / total) * 100.0, 2),
            )
        )
    return output


def _build_recommendations(
    metrics: dict[str, int],
    top_driver: str,
    new_changes: list[str],
) -> list[str]:
    actions: list[str] = []
    if metrics.get("failed_logins", 0) > 0:
        actions.append("Review failed login bursts and enforce MFA where missing.")
    if metrics.get("new_listeners", 0) > 0:
        actions.append("Validate newly exposed listening ports and close unneeded services.")
    if metrics.get("suspicious_execs", 0) > 0:
        actions.append("Investigate binaries running from temporary paths.")
    if top_driver == "process":
        actions.append("Reconcile new process inventory against approved software baseline.")
    if new_changes:
        actions.append("Validate high-severity changes introduced since yesterday.")
    if not actions:
        actions.append("Maintain current hardening baseline and monitor for drift.")
    return actions[:3]


def build_insight_bundle(
    events: list[dict[str, Any]],
    now: datetime | None = None,
    severity_weights: dict[str, int] | None = None,
) -> InsightBundle:
    if not events:
        raise ValueError("events cannot be empty")

    current = now or datetime.now(UTC)
    weights = severity_weights or {
        Severity.INFO.value: 1,
        Severity.WARN.value: 3,
        Severity.HIGH.value: 8,
    }

    grouped: dict[date, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        ts = _safe_ts(event.get("ts"))
        grouped[ts.date()].append(event)

    target_day = max(grouped.keys())
    target_events = grouped[target_day]

    history_days = sorted(day for day in grouped if day < target_day)
    prior_14 = history_days[-14:]
    prior_30 = history_days[-30:]

    today_metrics = _compute_day_metrics(grouped, target_day)
    prior_metrics = [_compute_day_metrics(grouped, day) for day in prior_14]
    baseline = compute_baseline(today_metrics, prior_metrics)

    raw_today = sum(weights.get(str(event.get("severity") or Severity.INFO.value), 0) for event in target_events)
    raw_30 = [
        sum(weights.get(str(event.get("severity") or Severity.INFO.value), 0) for event in grouped[day])
        for day in prior_30
    ]
    rolling_max = max(raw_30 + [raw_today]) if (raw_30 or raw_today > 0) else 30
    normalized_denominator = max(rolling_max, 30)
    risk_score = int(min(100, round((raw_today / normalized_denominator) * 100)))

    counts = {
        Severity.INFO.value: sum(1 for event in target_events if str(event.get("severity")) == Severity.INFO.value),
        Severity.WARN.value: sum(1 for event in target_events if str(event.get("severity")) == Severity.WARN.value),
        Severity.HIGH.value: sum(1 for event in target_events if str(event.get("severity")) == Severity.HIGH.value),
    }

    drivers = _driver_shares(target_events, weights)

    yesterday = target_day - timedelta(days=1)
    y_events = grouped.get(yesterday, [])
    today_fp = {
        _event_fingerprint(event): str(event.get("title") or "")
        for event in target_events
        if str(event.get("severity")) in {Severity.WARN.value, Severity.HIGH.value}
    }
    y_fp = {
        _event_fingerprint(event): str(event.get("title") or "")
        for event in y_events
        if str(event.get("severity")) in {Severity.WARN.value, Severity.HIGH.value}
    }

    new_changes = sorted(today_fp[fp] for fp in set(today_fp) - set(y_fp))
    resolved_changes = sorted(y_fp[fp] for fp in set(y_fp) - set(today_fp))

    insights: list[Insight] = []
    for metric_key in METRIC_KEYS:
        metric = baseline[metric_key]
        if metric.classification.value == "normal":
            continue
        source_map = {
            "failed_logins": Source.AUTH,
            "new_listeners": Source.NETWORK,
            "new_processes": Source.PROCESS,
            "suspicious_execs": Source.PROCESS,
        }
        severity = Severity.HIGH if metric.classification.value == "anomalous" else Severity.WARN
        title = f"{metric.metric} is {metric.ratio:.1f}x above 14-day median"
        evidence = metric.model_dump(mode="json")
        insights.append(
            Insight(
                ts=current,
                day=target_day,
                insight_type="anomaly",
                source=source_map.get(metric_key, Source.SYSTEM),
                severity=severity,
                title=title,
                explanation=(
                    "Anomaly rule: normal <1.5x, elevated 1.5x-2.9x, anomalous >=3x versus 14-day median."
                ),
                evidence=evidence,
                fingerprint=build_fingerprint(source_map.get(metric_key, Source.SYSTEM).value, title, evidence),
            )
        )

    for driver in drivers[:2]:
        if driver.percent <= 0:
            continue
        severity = Severity.WARN if driver.percent >= 40 else Severity.INFO
        title = f"Risk driver: {driver.category} ({driver.percent:.1f}%)"
        evidence = driver.model_dump(mode="json")
        insights.append(
            Insight(
                ts=current,
                day=target_day,
                insight_type="driver",
                source=Source.SYSTEM,
                severity=severity,
                title=title,
                explanation="Driver share is weighted category score divided by total weighted score for the day.",
                evidence=evidence,
                fingerprint=build_fingerprint(Source.SYSTEM.value, title, evidence),
            )
        )

    for change in new_changes[:10]:
        evidence = {"change": change, "change_type": "new"}
        title = f"New risk since yesterday: {change}"
        insights.append(
            Insight(
                ts=current,
                day=target_day,
                insight_type="delta",
                source=Source.SYSTEM,
                severity=Severity.WARN,
                title=title,
                explanation="Change was observed in today's WARN/HIGH set but not in yesterday's.",
                evidence=evidence,
                fingerprint=build_fingerprint(Source.SYSTEM.value, title, evidence),
            )
        )

    for change in resolved_changes[:10]:
        evidence = {"change": change, "change_type": "resolved"}
        title = f"Resolved since yesterday: {change}"
        insights.append(
            Insight(
                ts=current,
                day=target_day,
                insight_type="delta",
                source=Source.SYSTEM,
                severity=Severity.INFO,
                title=title,
                explanation="Change was present yesterday but not found in today's WARN/HIGH set.",
                evidence=evidence,
                fingerprint=build_fingerprint(Source.SYSTEM.value, title, evidence),
                status="resolved",
            )
        )

    recent_scores = [
        int(
            min(
                100,
                round(
                    (
                        sum(weights.get(str(event.get("severity") or Severity.INFO.value), 0) for event in grouped[day])
                        / normalized_denominator
                    )
                    * 100
                ),
            )
        )
        for day in history_days[-7:]
    ]
    avg_7d = mean(recent_scores) if recent_scores else float(risk_score)
    delta_vs_7d = round(risk_score - avg_7d, 2)
    top_driver = drivers[0].category if drivers else "none"

    anomalies = [insight.title for insight in insights if insight.insight_type == "anomaly"][:4]
    recommendations = _build_recommendations(today_metrics, top_driver, new_changes)

    brief = DailyBrief(
        day=target_day,
        risk_score=risk_score,
        delta_vs_7d_avg=delta_vs_7d,
        top_driver=top_driver,
        anomalies=anomalies,
        recommended_actions=recommendations,
    )

    return InsightBundle(
        day=target_day,
        risk_score=risk_score,
        raw_risk_score=raw_today,
        counts=counts,
        metrics=today_metrics,
        baseline=baseline,
        drivers=drivers,
        new_changes=new_changes,
        resolved_changes=resolved_changes,
        insights=insights,
        daily_brief=brief,
    )
