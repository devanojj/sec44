from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Severity(str, Enum):
    INFO = "INFO"
    WARN = "WARN"
    HIGH = "HIGH"


class Source(str, Enum):
    PROCESS = "process"
    LOGIN = "login"
    NETWORK = "network"
    FILEWATCH = "filewatch"
    SYSTEM = "system"


class EventIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    ts: str = Field(default_factory=lambda: datetime.now(UTC).isoformat(), min_length=20, max_length=64)
    source: Source
    severity: Severity
    title: str = Field(min_length=1, max_length=240)
    details: dict[str, Any] = Field(default_factory=dict)


class ListenerEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    ip: str
    port: int
    family: str
    pid: int | None = None
    process_name: str | None = None


class CollectorResult(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    events: list[EventIn] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
