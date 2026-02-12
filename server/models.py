from __future__ import annotations

from datetime import UTC, date, datetime

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def utc_now() -> datetime:
    return datetime.now(UTC)


class Org(Base):
    __tablename__ = "orgs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[str] = mapped_column(String(256), unique=True, nullable=False, index=True)
    org_name: Mapped[str] = mapped_column(String(256), nullable=False)
    api_key_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    ingest_rate_limit_per_minute: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (UniqueConstraint("org_id", "device_id", name="uq_devices_org_device"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    device_id: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    platform: Mapped[str] = mapped_column(String(32), nullable=False)
    agent_version: Mapped[str] = mapped_column(String(64), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    device_id: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    platform: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(4096), nullable=False)
    details_json: Mapped[str] = mapped_column(Text, nullable=False)


class InsightRow(Base):
    __tablename__ = "insights"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    device_id: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    day: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    insight_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(4096), nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_json: Mapped[str] = mapped_column(Text, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open", index=True)
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class DailyMetric(Base):
    __tablename__ = "daily_metrics"
    __table_args__ = (UniqueConstraint("org_id", "device_id", "day", name="uq_metrics_org_device_day"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    device_id: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    day: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    raw_risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    failed_logins: Mapped[int] = mapped_column(Integer, nullable=False)
    new_listeners: Mapped[int] = mapped_column(Integer, nullable=False)
    new_processes: Mapped[int] = mapped_column(Integer, nullable=False)
    suspicious_execs: Mapped[int] = mapped_column(Integer, nullable=False)
    counts_json: Mapped[str] = mapped_column(Text, nullable=False)
    baseline_json: Mapped[str] = mapped_column(Text, nullable=False)
    drivers_json: Mapped[str] = mapped_column(Text, nullable=False)
    new_changes_json: Mapped[str] = mapped_column(Text, nullable=False)
    resolved_changes_json: Mapped[str] = mapped_column(Text, nullable=False)
    brief_json: Mapped[str] = mapped_column(Text, nullable=False)
    delta_vs_7d: Mapped[str] = mapped_column(String(64), nullable=False)
    top_driver: Mapped[str] = mapped_column(String(128), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class Nonce(Base):
    __tablename__ = "nonces"
    __table_args__ = (UniqueConstraint("org_id", "device_id", "nonce", name="uq_nonce"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    device_id: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    nonce: Mapped[str] = mapped_column(String(128), nullable=False)
    seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)


class UserAccount(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("org_id", "username", name="uq_users_org_username"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[str] = mapped_column(String(256), ForeignKey("orgs.org_id", ondelete="CASCADE"), nullable=False)
    username: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="read_only")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_id_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


Index("idx_events_org_device_ts", Event.org_id, Event.device_id, Event.ts)
Index("idx_insights_org_device_day", InsightRow.org_id, InsightRow.device_id, InsightRow.day)
Index("idx_metrics_org_device_day", DailyMetric.org_id, DailyMetric.device_id, DailyMetric.day)
