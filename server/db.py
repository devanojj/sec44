from __future__ import annotations

import hashlib
import json
from contextlib import contextmanager
from datetime import UTC, date, datetime, timedelta
from typing import Any, Callable, Iterator

from sqlalchemy import Engine, and_, create_engine, delete, desc, func, select
from sqlalchemy.orm import Session, sessionmaker

from core.models import InsightBundle
from server.config import OrgSeed, UserSeed
from server.models import Base, DailyMetric, Device, Event, InsightRow, Nonce, Org, RefreshToken, UserAccount
from shared.schemas import IngestRequest
from shared.serialization import canonical_json_text


class ServerDatabase:
    def __init__(self, database_url: str) -> None:
        self.engine: Engine = create_engine(database_url, future=True, pool_pre_ping=True)
        self._session_factory = sessionmaker(bind=self.engine, autoflush=False, autocommit=False, future=True)

    def init_for_tests(self) -> None:
        Base.metadata.create_all(self.engine)

    def ping(self) -> None:
        with self.session() as db:
            db.execute(select(1))

    @contextmanager
    def session(self) -> Iterator[Session]:
        session = self._session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    @staticmethod
    def hash_secret(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def seed_orgs(self, orgs: list[OrgSeed]) -> None:
        with self.session() as db:
            for record in orgs:
                existing = db.execute(select(Org).where(Org.org_id == record.org_id)).scalar_one_or_none()
                if existing is None:
                    db.add(
                        Org(
                            org_id=record.org_id,
                            org_name=record.org_name,
                            api_key_hash=self.hash_secret(record.api_key),
                            ingest_rate_limit_per_minute=record.ingest_rate_limit_per_minute,
                            is_active=True,
                        )
                    )
                else:
                    existing.org_name = record.org_name
                    existing.api_key_hash = self.hash_secret(record.api_key)
                    existing.ingest_rate_limit_per_minute = record.ingest_rate_limit_per_minute
                    existing.is_active = True

    def seed_users(self, users: list[UserSeed], hash_password: Callable[[str], str]) -> None:
        if not users:
            return
        with self.session() as db:
            for item in users:
                existing = db.execute(
                    select(UserAccount).where(UserAccount.org_id == item.org_id, UserAccount.username == item.username)
                ).scalar_one_or_none()
                hashed = hash_password(item.password)
                if existing is None:
                    db.add(
                        UserAccount(
                            org_id=item.org_id,
                            username=item.username,
                            password_hash=hashed,
                            role=item.role,
                            is_active=True,
                        )
                    )
                else:
                    existing.password_hash = hashed
                    existing.role = item.role
                    existing.is_active = True

    def get_org(self, org_id: str) -> Org | None:
        with self.session() as db:
            return db.execute(select(Org).where(Org.org_id == org_id)).scalar_one_or_none()

    def get_user(self, org_id: str, username: str) -> UserAccount | None:
        with self.session() as db:
            return db.execute(
                select(UserAccount).where(UserAccount.org_id == org_id, UserAccount.username == username)
            ).scalar_one_or_none()

    def touch_user_login(self, user_id: int) -> None:
        with self.session() as db:
            user = db.execute(select(UserAccount).where(UserAccount.id == user_id)).scalar_one_or_none()
            if user is not None:
                user.last_login_at = datetime.now(UTC)

    def ingest_request(self, request: IngestRequest, seen_at: datetime, window_seconds: int) -> int:
        expires_at = seen_at + timedelta(seconds=window_seconds)
        with self.session() as db:
            org = db.execute(select(Org).where(Org.org_id == request.org_id)).scalar_one_or_none()
            if org is None or not org.is_active:
                return -1

            db.execute(delete(Nonce).where(Nonce.expires_at < seen_at))
            replay = db.execute(
                select(Nonce.id).where(
                    Nonce.org_id == request.org_id,
                    Nonce.device_id == request.device_id,
                    Nonce.nonce == request.nonce,
                )
            ).first()
            if replay is not None:
                return 0

            db.add(
                Nonce(
                    org_id=request.org_id,
                    device_id=request.device_id,
                    nonce=request.nonce,
                    seen_at=seen_at,
                    expires_at=expires_at,
                )
            )

            device = db.execute(
                select(Device).where(Device.org_id == request.org_id, Device.device_id == request.device_id)
            ).scalar_one_or_none()
            inferred_platform = request.events[0].platform.value if request.events else "unknown"
            if device is None:
                db.add(
                    Device(
                        org_id=request.org_id,
                        device_id=request.device_id,
                        platform=inferred_platform,
                        agent_version=request.agent_version,
                        first_seen_at=seen_at,
                        last_seen_at=seen_at,
                    )
                )
            else:
                device.platform = inferred_platform
                device.agent_version = request.agent_version
                device.last_seen_at = seen_at

            for event in request.events:
                db.add(
                    Event(
                        org_id=request.org_id,
                        device_id=request.device_id,
                        ts=event.ts,
                        source=event.source.value,
                        severity=event.severity.value,
                        platform=event.platform.value,
                        title=event.title,
                        details_json=canonical_json_text(event.details_json),
                    )
                )

        return len(request.events)

    def fetch_events_for_device(self, org_id: str, device_id: str, days: int = 31) -> list[dict[str, Any]]:
        cutoff = datetime.now(UTC) - timedelta(days=days)
        with self.session() as db:
            rows = list(
                db.execute(
                    select(Event)
                    .where(Event.org_id == org_id, Event.device_id == device_id, Event.ts >= cutoff)
                    .order_by(Event.ts.asc())
                ).scalars()
            )

        output: list[dict[str, Any]] = []
        for row in rows:
            try:
                details = json.loads(row.details_json)
            except json.JSONDecodeError:
                details = {}
            output.append(
                {
                    "ts": row.ts,
                    "source": row.source,
                    "severity": row.severity,
                    "platform": row.platform,
                    "title": row.title,
                    "details_json": details if isinstance(details, dict) else {},
                }
            )
        return output

    def persist_bundle(self, org_id: str, device_id: str, bundle: InsightBundle, dedup_minutes: int = 30) -> dict[str, int]:
        now = datetime.now(UTC)
        window_start = now - timedelta(minutes=dedup_minutes)
        inserted = 0
        suppressed = 0

        fingerprints = [insight.fingerprint for insight in bundle.insights]
        with self.session() as db:
            existing_rows = list(
                db.execute(
                    select(InsightRow).where(
                        InsightRow.org_id == org_id,
                        InsightRow.device_id == device_id,
                        InsightRow.fingerprint.in_(fingerprints),
                        InsightRow.last_seen >= window_start,
                    )
                ).scalars()
            )
            existing = {row.fingerprint: row for row in existing_rows}

            for insight in bundle.insights:
                row = existing.get(insight.fingerprint)
                if row is not None:
                    row.last_seen = now
                    row.count = int(row.count) + 1
                    suppressed += 1
                    continue
                db.add(
                    InsightRow(
                        org_id=org_id,
                        device_id=device_id,
                        day=insight.day,
                        ts=insight.ts,
                        insight_type=insight.insight_type,
                        source=insight.source.value,
                        severity=insight.severity.value,
                        title=insight.title,
                        explanation=insight.explanation,
                        evidence_json=canonical_json_text(insight.evidence),
                        fingerprint=insight.fingerprint,
                        status=insight.status,
                        count=1,
                        first_seen=now,
                        last_seen=now,
                    )
                )
                inserted += 1

            metric = db.execute(
                select(DailyMetric).where(
                    DailyMetric.org_id == org_id,
                    DailyMetric.device_id == device_id,
                    DailyMetric.day == bundle.day,
                )
            ).scalar_one_or_none()

            metric_payload = {
                "risk_score": int(bundle.risk_score),
                "raw_risk_score": int(bundle.raw_risk_score),
                "failed_logins": int(bundle.metrics.get("failed_logins", 0)),
                "new_listeners": int(bundle.metrics.get("new_listeners", 0)),
                "new_processes": int(bundle.metrics.get("new_processes", 0)),
                "suspicious_execs": int(bundle.metrics.get("suspicious_execs", 0)),
                "counts_json": canonical_json_text(bundle.counts),
                "baseline_json": canonical_json_text(
                    {key: value.model_dump(mode="json") for key, value in bundle.baseline.items()}
                ),
                "drivers_json": canonical_json_text([driver.model_dump(mode="json") for driver in bundle.drivers]),
                "new_changes_json": canonical_json_text(bundle.new_changes),
                "resolved_changes_json": canonical_json_text(bundle.resolved_changes),
                "brief_json": canonical_json_text(bundle.daily_brief.model_dump(mode="json")),
                "delta_vs_7d": str(bundle.daily_brief.delta_vs_7d_avg),
                "top_driver": bundle.daily_brief.top_driver,
                "updated_at": now,
            }

            if metric is None:
                db.add(DailyMetric(org_id=org_id, device_id=device_id, day=bundle.day, **metric_payload))
            else:
                metric.risk_score = metric_payload["risk_score"]
                metric.raw_risk_score = metric_payload["raw_risk_score"]
                metric.failed_logins = metric_payload["failed_logins"]
                metric.new_listeners = metric_payload["new_listeners"]
                metric.new_processes = metric_payload["new_processes"]
                metric.suspicious_execs = metric_payload["suspicious_execs"]
                metric.counts_json = metric_payload["counts_json"]
                metric.baseline_json = metric_payload["baseline_json"]
                metric.drivers_json = metric_payload["drivers_json"]
                metric.new_changes_json = metric_payload["new_changes_json"]
                metric.resolved_changes_json = metric_payload["resolved_changes_json"]
                metric.brief_json = metric_payload["brief_json"]
                metric.delta_vs_7d = metric_payload["delta_vs_7d"]
                metric.top_driver = metric_payload["top_driver"]
                metric.updated_at = metric_payload["updated_at"]

        return {"inserted": inserted, "suppressed": suppressed}

    def store_refresh_token(self, user_id: int, token_id: str, expires_at: datetime) -> None:
        token_hash = self.hash_secret(token_id)
        with self.session() as db:
            db.execute(delete(RefreshToken).where(RefreshToken.expires_at < datetime.now(UTC)))
            db.add(RefreshToken(user_id=user_id, token_id_hash=token_hash, expires_at=expires_at, revoked_at=None))

    def use_refresh_token(self, token_id: str) -> UserAccount | None:
        token_hash = self.hash_secret(token_id)
        now = datetime.now(UTC)
        with self.session() as db:
            token = db.execute(
                select(RefreshToken).where(
                    RefreshToken.token_id_hash == token_hash,
                    RefreshToken.revoked_at.is_(None),
                    RefreshToken.expires_at > now,
                )
            ).scalar_one_or_none()
            if token is None:
                return None
            token.revoked_at = now
            user = db.execute(select(UserAccount).where(UserAccount.id == token.user_id)).scalar_one_or_none()
            return user

    def fleet_top_devices(self, org_id: str, limit: int = 5) -> list[dict[str, Any]]:
        with self.session() as db:
            latest_day_subq = (
                select(DailyMetric.device_id, func.max(DailyMetric.day).label("max_day"))
                .where(DailyMetric.org_id == org_id)
                .group_by(DailyMetric.device_id)
                .subquery()
            )
            rows = db.execute(
                select(DailyMetric, Device)
                .join(
                    latest_day_subq,
                    and_(DailyMetric.device_id == latest_day_subq.c.device_id, DailyMetric.day == latest_day_subq.c.max_day),
                )
                .join(
                    Device,
                    and_(Device.org_id == DailyMetric.org_id, Device.device_id == DailyMetric.device_id),
                )
                .where(DailyMetric.org_id == org_id)
                .order_by(desc(DailyMetric.risk_score))
                .limit(max(1, min(limit, 50)))
            ).all()

        output: list[dict[str, Any]] = []
        for metric, device in rows:
            output.append(
                {
                    "org_id": metric.org_id,
                    "device_id": metric.device_id,
                    "platform": device.platform,
                    "day": metric.day.isoformat(),
                    "risk_score": metric.risk_score,
                    "delta_vs_7d": metric.delta_vs_7d,
                    "top_driver": metric.top_driver,
                    "failed_logins": metric.failed_logins,
                    "new_listeners": metric.new_listeners,
                    "new_processes": metric.new_processes,
                    "suspicious_execs": metric.suspicious_execs,
                }
            )
        return output

    def get_risk_trend(self, org_id: str, device_id: str, days: int) -> list[dict[str, Any]]:
        cutoff = date.today() - timedelta(days=max(1, min(days, 365)))
        with self.session() as db:
            rows = db.execute(
                select(DailyMetric)
                .where(
                    DailyMetric.org_id == org_id,
                    DailyMetric.device_id == device_id,
                    DailyMetric.day >= cutoff,
                )
                .order_by(DailyMetric.day.asc())
            ).scalars()
            metrics = list(rows)

        return [{"day": row.day.isoformat(), "risk_score": row.risk_score} for row in metrics]

    def list_alert_summary(self, org_id: str, device_id: str | None = None) -> dict[str, int]:
        with self.session() as db:
            stmt = select(InsightRow.severity, func.count(InsightRow.id)).where(InsightRow.org_id == org_id)
            if device_id:
                stmt = stmt.where(InsightRow.device_id == device_id)
            stmt = stmt.group_by(InsightRow.severity)
            rows = db.execute(stmt).all()

        output = {"INFO": 0, "WARN": 0, "HIGH": 0}
        for severity, count in rows:
            if severity in output:
                output[str(severity)] = int(count)
        return output

    def list_devices(self, org_id: str) -> list[Device]:
        with self.session() as db:
            return list(
                db.execute(select(Device).where(Device.org_id == org_id).order_by(Device.last_seen_at.desc())).scalars()
            )

    def list_events(
        self,
        org_id: str,
        severity: str | None = None,
        source: str | None = None,
        device_id: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[Event], int]:
        page_safe = max(1, page)
        size_safe = max(1, min(page_size, 200))
        offset = (page_safe - 1) * size_safe

        with self.session() as db:
            stmt = select(Event).where(Event.org_id == org_id)
            count_stmt = select(func.count(Event.id)).where(Event.org_id == org_id)
            if severity:
                stmt = stmt.where(Event.severity == severity)
                count_stmt = count_stmt.where(Event.severity == severity)
            if source:
                stmt = stmt.where(Event.source == source)
                count_stmt = count_stmt.where(Event.source == source)
            if device_id:
                stmt = stmt.where(Event.device_id == device_id)
                count_stmt = count_stmt.where(Event.device_id == device_id)

            total = int(db.execute(count_stmt).scalar_one())
            rows = list(db.execute(stmt.order_by(Event.ts.desc()).offset(offset).limit(size_safe)).scalars())
        return rows, total

    def list_insights(
        self,
        org_id: str,
        severity: str | None = None,
        source: str | None = None,
        status: str | None = None,
        device_id: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[InsightRow], int]:
        page_safe = max(1, page)
        size_safe = max(1, min(page_size, 200))
        offset = (page_safe - 1) * size_safe

        with self.session() as db:
            stmt = select(InsightRow).where(InsightRow.org_id == org_id)
            count_stmt = select(func.count(InsightRow.id)).where(InsightRow.org_id == org_id)
            if severity:
                stmt = stmt.where(InsightRow.severity == severity)
                count_stmt = count_stmt.where(InsightRow.severity == severity)
            if source:
                stmt = stmt.where(InsightRow.source == source)
                count_stmt = count_stmt.where(InsightRow.source == source)
            if status:
                stmt = stmt.where(InsightRow.status == status)
                count_stmt = count_stmt.where(InsightRow.status == status)
            if device_id:
                stmt = stmt.where(InsightRow.device_id == device_id)
                count_stmt = count_stmt.where(InsightRow.device_id == device_id)

            total = int(db.execute(count_stmt).scalar_one())
            rows = list(db.execute(stmt.order_by(InsightRow.ts.desc()).offset(offset).limit(size_safe)).scalars())
        return rows, total

    def get_device(self, org_id: str, device_id: str) -> Device | None:
        with self.session() as db:
            return db.execute(
                select(Device).where(Device.org_id == org_id, Device.device_id == device_id)
            ).scalar_one_or_none()

    def get_metric(self, org_id: str, device_id: str) -> DailyMetric | None:
        with self.session() as db:
            return db.execute(
                select(DailyMetric)
                .where(DailyMetric.org_id == org_id, DailyMetric.device_id == device_id)
                .order_by(DailyMetric.day.desc())
                .limit(1)
            ).scalar_one_or_none()

    def get_org_device_pairs(self) -> list[tuple[str, str]]:
        with self.session() as db:
            rows = db.execute(select(Device.org_id, Device.device_id)).all()
        return [(str(org_id), str(device_id)) for org_id, device_id in rows]

    def metrics_page(
        self,
        org_id: str,
        page: int,
        page_size: int,
        device_id: str | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        page_safe = max(1, page)
        size_safe = max(1, min(page_size, 200))
        offset = (page_safe - 1) * size_safe

        with self.session() as db:
            latest_day_subq = (
                select(DailyMetric.device_id, func.max(DailyMetric.day).label("max_day"))
                .where(DailyMetric.org_id == org_id)
                .group_by(DailyMetric.device_id)
                .subquery()
            )
            stmt = (
                select(DailyMetric)
                .join(
                    latest_day_subq,
                    and_(DailyMetric.device_id == latest_day_subq.c.device_id, DailyMetric.day == latest_day_subq.c.max_day),
                )
                .where(DailyMetric.org_id == org_id)
            )
            count_stmt = select(func.count(DailyMetric.id)).where(DailyMetric.org_id == org_id)
            if device_id:
                stmt = stmt.where(DailyMetric.device_id == device_id)
                count_stmt = count_stmt.where(DailyMetric.device_id == device_id)

            total = int(db.execute(count_stmt).scalar_one())
            rows = list(db.execute(stmt.order_by(desc(DailyMetric.risk_score)).offset(offset).limit(size_safe)).scalars())

        output: list[dict[str, Any]] = []
        for row in rows:
            drivers = []
            anomalies = []
            try:
                drivers_data = json.loads(row.drivers_json)
                if isinstance(drivers_data, list):
                    drivers = drivers_data[:3]
            except json.JSONDecodeError:
                drivers = []
            try:
                brief = json.loads(row.brief_json)
                if isinstance(brief, dict):
                    raw_anomalies = brief.get("anomalies", [])
                    if isinstance(raw_anomalies, list):
                        anomalies = [str(item) for item in raw_anomalies[:4]]
            except json.JSONDecodeError:
                anomalies = []

            output.append(
                {
                    "org_id": row.org_id,
                    "device_id": row.device_id,
                    "day": row.day.isoformat(),
                    "risk_score": row.risk_score,
                    "delta_vs_7d": row.delta_vs_7d,
                    "top_driver": row.top_driver,
                    "drivers": drivers,
                    "anomalies": anomalies,
                    "trend_7d": self.get_risk_trend(org_id=org_id, device_id=row.device_id, days=7),
                    "trend_30d": self.get_risk_trend(org_id=org_id, device_id=row.device_id, days=30),
                }
            )
        return output, total
