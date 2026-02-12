from __future__ import annotations

from datetime import UTC, date, datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class InsightType(str, Enum):
    ANOMALY = "anomaly"
    CHANGE = "change"
    DRIVER = "driver"
    ACTION = "action"
    POSTURE = "posture"


class InsightSource(str, Enum):
    AUTH = "auth"
    NETWORK = "network"
    PROCESS = "process"
    FILEWATCH = "filewatch"
    SYSTEM = "system"


class InsightSeverity(str, Enum):
    INFO = "INFO"
    WARN = "WARN"
    HIGH = "HIGH"


class InsightConfidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class InsightStatus(str, Enum):
    OPEN = "open"
    RESOLVED = "resolved"
    ACKNOWLEDGED = "acknowledged"


class BaselineClassification(str, Enum):
    NORMAL = "normal"
    ELEVATED = "elevated"
    ANOMALOUS = "anomalous"


class BaselineDelta(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    signal: Literal[
        "failed_logins_24h",
        "new_listeners_24h",
        "new_processes_24h",
        "suspicious_exec_path_24h",
    ]
    today: int = Field(ge=0)
    baseline: float = Field(ge=0)
    ratio: float = Field(ge=0)
    classification: BaselineClassification

    @property
    def ratio_text(self) -> str:
        return f"{self.ratio:.1f}x above baseline"


class RiskDriver(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    category: Literal[
        "network_exposure",
        "process_anomaly",
        "auth_anomaly",
        "filewatch_anomaly",
    ]
    score: float = Field(ge=0)
    percent: float = Field(ge=0, le=100)
    explanation: str = Field(min_length=1, max_length=512)


class InsightCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    ts: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    insight_type: InsightType
    source: InsightSource
    severity: InsightSeverity
    confidence: InsightConfidence
    title: str = Field(min_length=1, max_length=240)
    explanation: str = Field(min_length=1, max_length=1200)
    evidence: dict[str, Any] = Field(default_factory=dict)
    action_text: str = Field(min_length=1, max_length=600)
    fingerprint: str | None = Field(default=None, min_length=8, max_length=128)
    status: InsightStatus = InsightStatus.OPEN


class InsightRecord(InsightCreate):
    id: int = Field(ge=1)
    first_seen: str
    last_seen: str
    count: int = Field(ge=1)


class DailyMetricsRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    date: str
    risk_score: int = Field(ge=0, le=100)
    high_count: int = Field(ge=0)
    warn_count: int = Field(ge=0)
    info_count: int = Field(ge=0)
    failed_logins: int = Field(ge=0)
    new_listeners: int = Field(ge=0)
    new_processes: int = Field(ge=0)
    suspicious_execs: int = Field(ge=0)
    baseline_deltas: dict[str, Any] = Field(default_factory=dict)
    drivers: list[RiskDriver] = Field(default_factory=list)
    updated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())

    @field_validator("date")
    @classmethod
    def validate_date(cls, value: str) -> str:
        date.fromisoformat(value)
        return value


class DailyBrief(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    date: str
    risk_score: int = Field(ge=0, le=100)
    delta_vs_7d_avg: float
    top_risk_driver: str = Field(min_length=1, max_length=128)
    unusual_behaviors: list[str] = Field(default_factory=list, min_length=0, max_length=4)
    priority_actions: list[str] = Field(default_factory=list, min_length=0, max_length=5)


class PostureTrend(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    risk_score_today: int = Field(ge=0, le=100)
    risk_score_7d_avg: float = Field(ge=0, le=100)
    high_alerts_today: int = Field(ge=0)
    high_alerts_7d_avg: float = Field(ge=0)
    status: Literal["Improving", "Stable", "Regressing"]
    high_alert_series_7d: list[int] = Field(default_factory=list)


class DailyDeltaPanel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    new_risks: list[dict[str, Any]] = Field(default_factory=list)
    resolved_risks: list[dict[str, Any]] = Field(default_factory=list)
