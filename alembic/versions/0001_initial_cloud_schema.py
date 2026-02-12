"""initial cloud schema with auth and ingest protections

Revision ID: 0001_initial_cloud_schema
Revises: None
Create Date: 2026-02-12 00:00:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0001_initial_cloud_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "orgs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("org_id", sa.String(length=256), nullable=False),
        sa.Column("org_name", sa.String(length=256), nullable=False),
        sa.Column("api_key_hash", sa.String(length=128), nullable=False),
        sa.Column("ingest_rate_limit_per_minute", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("org_id", name="uq_orgs_org_id"),
    )
    op.create_index("ix_orgs_org_id", "orgs", ["org_id"], unique=True)

    op.create_table(
        "devices",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("org_id", sa.String(length=256), nullable=False),
        sa.Column("device_id", sa.String(length=256), nullable=False),
        sa.Column("platform", sa.String(length=32), nullable=False),
        sa.Column("agent_version", sa.String(length=64), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("org_id", "device_id", name="uq_devices_org_device"),
    )
    op.create_index("ix_devices_org_id", "devices", ["org_id"], unique=False)
    op.create_index("ix_devices_device_id", "devices", ["device_id"], unique=False)

    op.create_table(
        "events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("org_id", sa.String(length=256), nullable=False),
        sa.Column("device_id", sa.String(length=256), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("platform", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=4096), nullable=False),
        sa.Column("details_json", sa.Text(), nullable=False),
    )
    op.create_index("ix_events_org_id", "events", ["org_id"], unique=False)
    op.create_index("ix_events_device_id", "events", ["device_id"], unique=False)
    op.create_index("ix_events_ts", "events", ["ts"], unique=False)
    op.create_index("ix_events_source", "events", ["source"], unique=False)
    op.create_index("ix_events_severity", "events", ["severity"], unique=False)
    op.create_index("idx_events_org_device_ts", "events", ["org_id", "device_id", "ts"], unique=False)

    op.create_table(
        "insights",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("org_id", sa.String(length=256), nullable=False),
        sa.Column("device_id", sa.String(length=256), nullable=False),
        sa.Column("day", sa.Date(), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("insight_type", sa.String(length=32), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("title", sa.String(length=4096), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("evidence_json", sa.Text(), nullable=False),
        sa.Column("fingerprint", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="open"),
        sa.Column("count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_insights_org_id", "insights", ["org_id"], unique=False)
    op.create_index("ix_insights_device_id", "insights", ["device_id"], unique=False)
    op.create_index("ix_insights_day", "insights", ["day"], unique=False)
    op.create_index("ix_insights_insight_type", "insights", ["insight_type"], unique=False)
    op.create_index("ix_insights_source", "insights", ["source"], unique=False)
    op.create_index("ix_insights_severity", "insights", ["severity"], unique=False)
    op.create_index("ix_insights_fingerprint", "insights", ["fingerprint"], unique=False)
    op.create_index("ix_insights_status", "insights", ["status"], unique=False)
    op.create_index("idx_insights_org_device_day", "insights", ["org_id", "device_id", "day"], unique=False)

    op.create_table(
        "daily_metrics",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("org_id", sa.String(length=256), nullable=False),
        sa.Column("device_id", sa.String(length=256), nullable=False),
        sa.Column("day", sa.Date(), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("raw_risk_score", sa.Integer(), nullable=False),
        sa.Column("failed_logins", sa.Integer(), nullable=False),
        sa.Column("new_listeners", sa.Integer(), nullable=False),
        sa.Column("new_processes", sa.Integer(), nullable=False),
        sa.Column("suspicious_execs", sa.Integer(), nullable=False),
        sa.Column("counts_json", sa.Text(), nullable=False),
        sa.Column("baseline_json", sa.Text(), nullable=False),
        sa.Column("drivers_json", sa.Text(), nullable=False),
        sa.Column("new_changes_json", sa.Text(), nullable=False),
        sa.Column("resolved_changes_json", sa.Text(), nullable=False),
        sa.Column("brief_json", sa.Text(), nullable=False),
        sa.Column("delta_vs_7d", sa.String(length=64), nullable=False),
        sa.Column("top_driver", sa.String(length=128), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("org_id", "device_id", "day", name="uq_metrics_org_device_day"),
    )
    op.create_index("ix_daily_metrics_org_id", "daily_metrics", ["org_id"], unique=False)
    op.create_index("ix_daily_metrics_device_id", "daily_metrics", ["device_id"], unique=False)
    op.create_index("ix_daily_metrics_day", "daily_metrics", ["day"], unique=False)
    op.create_index("idx_metrics_org_device_day", "daily_metrics", ["org_id", "device_id", "day"], unique=False)

    op.create_table(
        "nonces",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("org_id", sa.String(length=256), nullable=False),
        sa.Column("device_id", sa.String(length=256), nullable=False),
        sa.Column("nonce", sa.String(length=128), nullable=False),
        sa.Column("seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("org_id", "device_id", "nonce", name="uq_nonce"),
    )
    op.create_index("ix_nonces_org_id", "nonces", ["org_id"], unique=False)
    op.create_index("ix_nonces_device_id", "nonces", ["device_id"], unique=False)
    op.create_index("ix_nonces_expires_at", "nonces", ["expires_at"], unique=False)

    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("org_id", sa.String(length=256), nullable=False),
        sa.Column("username", sa.String(length=128), nullable=False),
        sa.Column("password_hash", sa.String(length=512), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.org_id"], ondelete="CASCADE"),
        sa.UniqueConstraint("org_id", "username", name="uq_users_org_username"),
    )
    op.create_index("ix_users_username", "users", ["username"], unique=False)

    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("token_id_hash", sa.String(length=128), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("token_id_hash", name="uq_refresh_token_hash"),
    )
    op.create_index("ix_refresh_tokens_token_id_hash", "refresh_tokens", ["token_id_hash"], unique=True)
    op.create_index("ix_refresh_tokens_expires_at", "refresh_tokens", ["expires_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_refresh_tokens_expires_at", table_name="refresh_tokens")
    op.drop_index("ix_refresh_tokens_token_id_hash", table_name="refresh_tokens")
    op.drop_table("refresh_tokens")

    op.drop_index("ix_users_username", table_name="users")
    op.drop_table("users")

    op.drop_index("ix_nonces_expires_at", table_name="nonces")
    op.drop_index("ix_nonces_device_id", table_name="nonces")
    op.drop_index("ix_nonces_org_id", table_name="nonces")
    op.drop_table("nonces")

    op.drop_index("idx_metrics_org_device_day", table_name="daily_metrics")
    op.drop_index("ix_daily_metrics_day", table_name="daily_metrics")
    op.drop_index("ix_daily_metrics_device_id", table_name="daily_metrics")
    op.drop_index("ix_daily_metrics_org_id", table_name="daily_metrics")
    op.drop_table("daily_metrics")

    op.drop_index("idx_insights_org_device_day", table_name="insights")
    op.drop_index("ix_insights_status", table_name="insights")
    op.drop_index("ix_insights_fingerprint", table_name="insights")
    op.drop_index("ix_insights_severity", table_name="insights")
    op.drop_index("ix_insights_source", table_name="insights")
    op.drop_index("ix_insights_insight_type", table_name="insights")
    op.drop_index("ix_insights_day", table_name="insights")
    op.drop_index("ix_insights_device_id", table_name="insights")
    op.drop_index("ix_insights_org_id", table_name="insights")
    op.drop_table("insights")

    op.drop_index("idx_events_org_device_ts", table_name="events")
    op.drop_index("ix_events_severity", table_name="events")
    op.drop_index("ix_events_source", table_name="events")
    op.drop_index("ix_events_ts", table_name="events")
    op.drop_index("ix_events_device_id", table_name="events")
    op.drop_index("ix_events_org_id", table_name="events")
    op.drop_table("events")

    op.drop_index("ix_devices_device_id", table_name="devices")
    op.drop_index("ix_devices_org_id", table_name="devices")
    op.drop_table("devices")

    op.drop_index("ix_orgs_org_id", table_name="orgs")
    op.drop_table("orgs")
