from __future__ import annotations

import json
from datetime import UTC, date, datetime, time, timedelta
from typing import Any

from mac_watchdog.db import Database
from mac_watchdog.insights.drivers import compute_driver_breakdown
from mac_watchdog.insights.schemas import DailyMetricsRecord, RiskDriver
from mac_watchdog.sanitizer import safe_json_dumps


class MetricsService:
    def __init__(self, db: Database, severity_weights: dict[str, int]) -> None:
        self.db = db
        self.severity_weights = severity_weights
        self.static_weight_cap = 40

    def _weighted(self, info_count: int, warn_count: int, high_count: int) -> int:
        return (
            info_count * self.severity_weights.get("INFO", 1)
            + warn_count * self.severity_weights.get("WARN", 3)
            + high_count * self.severity_weights.get("HIGH", 8)
        )

    def _risk_score(self, daily_weighted: int, rolling_max: int) -> int:
        return min(100, round(100 * daily_weighted / max(1, rolling_max)))

    def _rolling_max_weighted(self, date_value: date, today_weighted: int) -> int:
        start = (date_value - timedelta(days=29)).isoformat()
        end = date_value.isoformat()
        rows = self.db.fetch_all(
            """
            SELECT info_count, warn_count, high_count
            FROM daily_metrics
            WHERE date >= ? AND date <= ?
            """,
            (start, end),
        )

        weighted_values = [today_weighted]
        for row in rows:
            weighted_values.append(
                self._weighted(
                    int(row["info_count"]),
                    int(row["warn_count"]),
                    int(row["high_count"]),
                )
            )
        return max([self.static_weight_cap, *weighted_values])

    def _signal_counts(self, events: list[dict[str, Any]]) -> dict[str, int]:
        failed_logins = 0
        new_listeners = 0
        new_processes = 0
        suspicious_execs = 0

        for event in events:
            title = str(event.get("title") or "")
            source = str(event.get("source") or "")
            details = event.get("details") if isinstance(event.get("details"), dict) else {}

            if title == "Authentication failures observed":
                failed_logins += int(details.get("count") or 0)
            if source == "network" and "listener" in title.lower() and "snapshot" not in title.lower():
                if str(event.get("severity")) in {"WARN", "HIGH"}:
                    new_listeners += 1
            if title == "New process observed":
                new_processes += 1
            if title == "Process running from unusual path":
                suspicious_execs += 1

        return {
            "failed_logins_24h": failed_logins,
            "new_listeners_24h": new_listeners,
            "new_processes_24h": new_processes,
            "suspicious_exec_path_24h": suspicious_execs,
        }

    def _to_metrics_record(
        self,
        date_value: date,
        events: list[dict[str, Any]],
        baseline_deltas: dict[str, Any],
        drivers: list[RiskDriver],
    ) -> DailyMetricsRecord:
        info_count = sum(1 for event in events if event.get("severity") == "INFO")
        warn_count = sum(1 for event in events if event.get("severity") == "WARN")
        high_count = sum(1 for event in events if event.get("severity") == "HIGH")

        signal_counts = self._signal_counts(events)
        daily_weighted = self._weighted(info_count, warn_count, high_count)
        rolling_max = self._rolling_max_weighted(date_value, daily_weighted)

        formula_details = {
            "formula": "risk_score=min(100,round(100*daily_weighted/max(1,rolling_max_30d)))",
            "daily_weighted": daily_weighted,
            "rolling_max_30d": rolling_max,
            "weights": self.severity_weights,
            "static_weight_cap": self.static_weight_cap,
        }
        baseline_with_formula = dict(baseline_deltas)
        baseline_with_formula["_score_formula"] = formula_details

        return DailyMetricsRecord(
            date=date_value.isoformat(),
            risk_score=self._risk_score(daily_weighted, rolling_max),
            high_count=high_count,
            warn_count=warn_count,
            info_count=info_count,
            failed_logins=signal_counts["failed_logins_24h"],
            new_listeners=signal_counts["new_listeners_24h"],
            new_processes=signal_counts["new_processes_24h"],
            suspicious_execs=signal_counts["suspicious_exec_path_24h"],
            baseline_deltas=baseline_with_formula,
            drivers=drivers,
            updated_at=datetime.now(UTC).isoformat(),
        )

    def upsert_daily_metrics(self, record: DailyMetricsRecord) -> None:
        self.db.execute(
            """
            INSERT INTO daily_metrics(
              date, risk_score, high_count, warn_count, info_count,
              failed_logins, new_listeners, new_processes, suspicious_execs,
              baseline_deltas_json, drivers_json, updated_at
            )
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(date) DO UPDATE SET
              risk_score = excluded.risk_score,
              high_count = excluded.high_count,
              warn_count = excluded.warn_count,
              info_count = excluded.info_count,
              failed_logins = excluded.failed_logins,
              new_listeners = excluded.new_listeners,
              new_processes = excluded.new_processes,
              suspicious_execs = excluded.suspicious_execs,
              baseline_deltas_json = excluded.baseline_deltas_json,
              drivers_json = excluded.drivers_json,
              updated_at = excluded.updated_at
            """,
            (
                record.date,
                record.risk_score,
                record.high_count,
                record.warn_count,
                record.info_count,
                record.failed_logins,
                record.new_listeners,
                record.new_processes,
                record.suspicious_execs,
                safe_json_dumps(record.baseline_deltas),
                safe_json_dumps([driver.model_dump() for driver in record.drivers]),
                record.updated_at,
            ),
        )

    def build_and_store_metrics(
        self,
        date_value: date,
        events: list[dict[str, Any]],
        baseline_deltas: dict[str, Any],
    ) -> DailyMetricsRecord:
        drivers = compute_driver_breakdown(events, self.severity_weights)
        record = self._to_metrics_record(date_value, events, baseline_deltas, drivers)
        self.upsert_daily_metrics(record)
        return record

    def get_metrics(self, date_value: str) -> DailyMetricsRecord | None:
        row = self.db.fetch_one(
            """
            SELECT date, risk_score, high_count, warn_count, info_count,
                   failed_logins, new_listeners, new_processes, suspicious_execs,
                   baseline_deltas_json, drivers_json, updated_at
            FROM daily_metrics WHERE date = ?
            """,
            (date_value,),
        )
        if row is None:
            return None

        try:
            baseline_deltas = json.loads(str(row["baseline_deltas_json"]))
        except json.JSONDecodeError:
            baseline_deltas = {}

        try:
            drivers_raw = json.loads(str(row["drivers_json"]))
        except json.JSONDecodeError:
            drivers_raw = []
        drivers = [RiskDriver.model_validate(item) for item in drivers_raw if isinstance(item, dict)]

        return DailyMetricsRecord(
            date=str(row["date"]),
            risk_score=int(row["risk_score"]),
            high_count=int(row["high_count"]),
            warn_count=int(row["warn_count"]),
            info_count=int(row["info_count"]),
            failed_logins=int(row["failed_logins"]),
            new_listeners=int(row["new_listeners"]),
            new_processes=int(row["new_processes"]),
            suspicious_execs=int(row["suspicious_execs"]),
            baseline_deltas=baseline_deltas,
            drivers=drivers,
            updated_at=str(row["updated_at"]),
        )

    def list_recent_metrics(self, days: int, end_date: date | None = None) -> list[DailyMetricsRecord]:
        end = end_date or datetime.now(UTC).date()
        start = (end - timedelta(days=max(days - 1, 0))).isoformat()
        rows = self.db.fetch_all(
            """
            SELECT date FROM daily_metrics
            WHERE date >= ? AND date <= ?
            ORDER BY date ASC
            """,
            (start, end.isoformat()),
        )

        metrics: list[DailyMetricsRecord] = []
        for row in rows:
            metric = self.get_metrics(str(row["date"]))
            if metric is not None:
                metrics.append(metric)
        return metrics

    def prior_signal_history(self, target_date: date, days: int = 14) -> list[dict[str, int]]:
        start = (target_date - timedelta(days=days)).isoformat()
        end = (target_date - timedelta(days=1)).isoformat()
        rows = self.db.fetch_all(
            """
            SELECT failed_logins, new_listeners, new_processes, suspicious_execs
            FROM daily_metrics
            WHERE date >= ? AND date <= ?
            ORDER BY date ASC
            """,
            (start, end),
        )

        history: list[dict[str, int]] = []
        for row in rows:
            history.append(
                {
                    "failed_logins_24h": int(row["failed_logins"]),
                    "new_listeners_24h": int(row["new_listeners"]),
                    "new_processes_24h": int(row["new_processes"]),
                    "suspicious_exec_path_24h": int(row["suspicious_execs"]),
                }
            )
        return history

    def events_for_day(self, date_value: date) -> list[dict[str, Any]]:
        start = datetime.combine(date_value, time.min, tzinfo=UTC)
        end = start + timedelta(days=1)
        return self.db.get_events_between(start.isoformat(), end.isoformat())

    def backfill_daily_metrics(self) -> int:
        row = self.db.fetch_one(
            "SELECT MIN(substr(ts,1,10)) AS min_day, MAX(substr(ts,1,10)) AS max_day FROM events"
        )
        if row is None or row["min_day"] is None or row["max_day"] is None:
            return 0

        start = date.fromisoformat(str(row["min_day"]))
        end = date.fromisoformat(str(row["max_day"]))

        inserted = 0
        current = start
        while current <= end:
            if self.get_metrics(current.isoformat()) is None:
                events = self.events_for_day(current)
                # Backfill cannot reconstruct historical baselines reliably; set explicit fallback metadata.
                baseline = {
                    "_backfill": {
                        "note": "Computed from event history without complete prior baselines.",
                        "mode": "best_effort",
                    }
                }
                self.build_and_store_metrics(current, events, baseline)
                inserted += 1
            current += timedelta(days=1)

        return inserted
