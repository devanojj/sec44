from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from mac_watchdog.db import Database
from mac_watchdog.insights.dedup import build_fingerprint, within_window
from mac_watchdog.insights.schemas import (
    InsightConfidence,
    InsightCreate,
    InsightRecord,
    InsightSeverity,
    InsightSource,
    InsightStatus,
    InsightType,
)
from mac_watchdog.sanitizer import safe_json_dumps, sanitize_text

CONFIDENCE_RANK = {
    InsightConfidence.LOW.value: 1,
    InsightConfidence.MEDIUM.value: 2,
    InsightConfidence.HIGH.value: 3,
}
SEVERITY_RANK = {
    InsightSeverity.INFO.value: 1,
    InsightSeverity.WARN.value: 2,
    InsightSeverity.HIGH.value: 3,
}


class InsightService:
    def __init__(self, db: Database, dedup_window_minutes: int = 30) -> None:
        self.db = db
        self.dedup_window_minutes = max(1, dedup_window_minutes)

    def _row_to_record(self, row: Any) -> InsightRecord:
        try:
            details = json.loads(str(row["evidence_json"]))
        except json.JSONDecodeError:
            details = {}
        return InsightRecord(
            id=int(row["id"]),
            ts=str(row["ts"]),
            insight_type=InsightType(str(row["insight_type"])),
            source=InsightSource(str(row["source"])),
            severity=InsightSeverity(str(row["severity"])),
            confidence=InsightConfidence(str(row["confidence"])),
            title=str(row["title"]),
            explanation=str(row["explanation"]),
            evidence=details if isinstance(details, dict) else {},
            action_text=str(row["action_text"]),
            fingerprint=str(row["fingerprint"]),
            status=InsightStatus(str(row["status"])),
            first_seen=str(row["first_seen"]),
            last_seen=str(row["last_seen"]),
            count=int(row["count"]),
        )

    def _effective_fingerprint(self, insight: InsightCreate) -> str:
        if insight.fingerprint:
            return insight.fingerprint
        return build_fingerprint(insight.source.value, insight.title, insight.evidence)

    def _load_latest_by_fingerprint(self, fingerprint: str) -> InsightRecord | None:
        row = self.db.fetch_one(
            """
            SELECT id, ts, insight_type, source, severity, confidence, title, explanation,
                   evidence_json, action_text, fingerprint, status, first_seen, last_seen, count
            FROM insights
            WHERE fingerprint = ?
            ORDER BY last_seen DESC
            LIMIT 1
            """,
            (fingerprint,),
        )
        if row is None:
            return None
        return self._row_to_record(row)

    def record_insight(self, insight: InsightCreate) -> InsightRecord:
        now_ts = sanitize_text(insight.ts)
        fingerprint = self._effective_fingerprint(insight)
        existing = self._load_latest_by_fingerprint(fingerprint)

        if existing and within_window(existing.last_seen, now_ts, self.dedup_window_minutes):
            severity = existing.severity
            if SEVERITY_RANK[insight.severity.value] > SEVERITY_RANK[existing.severity.value]:
                severity = insight.severity

            confidence = existing.confidence
            if CONFIDENCE_RANK[insight.confidence.value] > CONFIDENCE_RANK[existing.confidence.value]:
                confidence = insight.confidence

            self.db.execute(
                """
                UPDATE insights
                SET ts = ?,
                    severity = ?,
                    confidence = ?,
                    explanation = ?,
                    evidence_json = ?,
                    action_text = ?,
                    last_seen = ?,
                    count = count + 1,
                    status = ?
                WHERE id = ?
                """,
                (
                    now_ts,
                    severity.value,
                    confidence.value,
                    sanitize_text(insight.explanation),
                    safe_json_dumps(insight.evidence),
                    sanitize_text(insight.action_text),
                    now_ts,
                    insight.status.value,
                    existing.id,
                ),
            )
            updated = self._load_latest_by_fingerprint(fingerprint)
            if updated is None:
                raise RuntimeError("failed to reload updated insight")
            return updated

        self.db.execute(
            """
            INSERT INTO insights(
              ts, insight_type, source, severity, confidence,
              title, explanation, evidence_json, action_text, fingerprint,
              status, first_seen, last_seen, count
            )
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                now_ts,
                insight.insight_type.value,
                insight.source.value,
                insight.severity.value,
                insight.confidence.value,
                sanitize_text(insight.title),
                sanitize_text(insight.explanation),
                safe_json_dumps(insight.evidence),
                sanitize_text(insight.action_text),
                fingerprint,
                insight.status.value,
                now_ts,
                now_ts,
                1,
            ),
        )
        created = self._load_latest_by_fingerprint(fingerprint)
        if created is None:
            raise RuntimeError("failed to load inserted insight")
        return created

    def bulk_record(self, insights: list[InsightCreate]) -> list[InsightRecord]:
        out: list[InsightRecord] = []
        for insight in insights:
            out.append(self.record_insight(insight))
        return out

    def list_insights(
        self,
        severity: str | None = None,
        source: str | None = None,
        status: str | None = None,
        start_ts: str | None = None,
        end_ts: str | None = None,
        page: int = 1,
        page_size: int = 30,
    ) -> list[InsightRecord]:
        clauses: list[str] = []
        params: list[Any] = []
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if source:
            clauses.append("source = ?")
            params.append(source)
        if status:
            clauses.append("status = ?")
            params.append(status)
        if start_ts:
            clauses.append("ts >= ?")
            params.append(start_ts)
        if end_ts:
            clauses.append("ts <= ?")
            params.append(end_ts)

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        page_safe = max(page, 1)
        size_safe = min(max(page_size, 1), 100)
        offset = (page_safe - 1) * size_safe

        rows = self.db.fetch_all(
            """
            SELECT id, ts, insight_type, source, severity, confidence, title, explanation,
                   evidence_json, action_text, fingerprint, status, first_seen, last_seen, count
            FROM insights
            """
            + where_sql
            + " ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?",
            (*params, size_safe, offset),
        )

        return [self._row_to_record(row) for row in rows]

    def open_priority_actions(self, limit: int = 5) -> list[InsightRecord]:
        rows = self.db.fetch_all(
            """
            SELECT id, ts, insight_type, source, severity, confidence, title, explanation,
                   evidence_json, action_text, fingerprint, status, first_seen, last_seen, count
            FROM insights
            WHERE status = 'open'
            ORDER BY
                CASE severity WHEN 'HIGH' THEN 3 WHEN 'WARN' THEN 2 ELSE 1 END DESC,
                CASE confidence WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 ELSE 1 END DESC,
                count DESC,
                last_seen DESC
            LIMIT ?
            """,
            (max(1, min(limit, 20)),),
        )
        return [self._row_to_record(row) for row in rows]

    def resolve_absent_change_insights(self, active_fingerprints: set[str], now_ts: str) -> int:
        rows = self.db.fetch_all(
            """
            SELECT id, fingerprint
            FROM insights
            WHERE status = 'open' AND insight_type = 'change'
            """
        )
        stale_ids = [int(row["id"]) for row in rows if str(row["fingerprint"]) not in active_fingerprints]
        if not stale_ids:
            return 0

        placeholders = ",".join("?" for _ in stale_ids)
        params: list[Any] = [now_ts]
        params.extend(stale_ids)
        self.db.execute(
            "UPDATE insights SET status = 'resolved', last_seen = ? WHERE id IN (" + placeholders + ")",
            tuple(params),
        )
        return len(stale_ids)

    def backfill_from_events(self, max_rows: int = 2500) -> int:
        rows = self.db.fetch_all(
            """
            SELECT ts, source, severity, title, details_json
            FROM events
            WHERE severity IN ('WARN', 'HIGH')
            ORDER BY ts ASC
            LIMIT ?
            """,
            (max_rows,),
        )
        created = 0
        for row in rows:
            try:
                evidence = json.loads(str(row["details_json"]))
            except json.JSONDecodeError:
                evidence = {}

            source_raw = str(row["source"])
            if source_raw == "login":
                source = InsightSource.AUTH
            elif source_raw == "network":
                source = InsightSource.NETWORK
            elif source_raw == "process":
                source = InsightSource.PROCESS
            elif source_raw == "filewatch":
                source = InsightSource.FILEWATCH
            else:
                source = InsightSource.SYSTEM

            insight = InsightCreate(
                ts=str(row["ts"]),
                insight_type=InsightType.CHANGE,
                source=source,
                severity=InsightSeverity(str(row["severity"])),
                confidence=InsightConfidence.MEDIUM,
                title=f"Backfilled: {row['title']}",
                explanation="Rule: backfilled from historical WARN/HIGH event to preserve investigation context.",
                evidence=evidence if isinstance(evidence, dict) else {},
                action_text="Review the related raw evidence in the Events view.",
            )
            self.record_insight(insight)
            created += 1

        return created

    def insight_counts_by_severity(self, start_ts: str | None = None) -> dict[str, int]:
        params: tuple[Any, ...]
        sql = "SELECT severity, COUNT(*) AS c FROM insights"
        if start_ts:
            sql += " WHERE ts >= ?"
            params = (start_ts,)
        else:
            params = ()
        sql += " GROUP BY severity"
        rows = self.db.fetch_all(sql, params)
        result = {"INFO": 0, "WARN": 0, "HIGH": 0}
        for row in rows:
            result[str(row["severity"])] = int(row["c"])
        return result
