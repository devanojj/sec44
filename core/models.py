from __future__ import annotations

from datetime import date, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from shared.enums import Severity, Source


class BaselineClassification(str, Enum):
    NORMAL = "normal"
    ELEVATED = "elevated"
    ANOMALOUS = "anomalous"


class BaselineMetric(BaseModel):
    model_config = ConfigDict(extra="forbid")

    metric: str
    today: int = Field(ge=0)
    baseline: float = Field(ge=0)
    ratio: float = Field(ge=0)
    classification: BaselineClassification


class DriverShare(BaseModel):
    model_config = ConfigDict(extra="forbid")

    category: str
    score: float = Field(ge=0)
    percent: float = Field(ge=0, le=100)


class Insight(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ts: datetime
    day: date
    insight_type: str
    source: Source
    severity: Severity
    title: str
    explanation: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    fingerprint: str
    status: str = "open"


class DailyBrief(BaseModel):
    model_config = ConfigDict(extra="forbid")

    day: date
    risk_score: int = Field(ge=0, le=100)
    delta_vs_7d_avg: float
    top_driver: str
    anomalies: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)


class InsightBundle(BaseModel):
    model_config = ConfigDict(extra="forbid")

    day: date
    risk_score: int = Field(ge=0, le=100)
    raw_risk_score: int = Field(ge=0)
    counts: dict[str, int]
    metrics: dict[str, int]
    baseline: dict[str, BaselineMetric]
    drivers: list[DriverShare]
    new_changes: list[str]
    resolved_changes: list[str]
    insights: list[Insight]
    daily_brief: DailyBrief
