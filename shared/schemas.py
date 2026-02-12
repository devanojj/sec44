from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from shared.constants import MAX_EVENTS_PER_BATCH, MAX_STRING_LEN, NONCE_MAX_LENGTH, NONCE_MIN_LENGTH
from shared.enums import Platform, Severity, Source
from shared.sanitization import sanitize_json_object, sanitize_text


class EventEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ts: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source: Source
    severity: Severity
    platform: Platform
    title: str = Field(min_length=1, max_length=MAX_STRING_LEN)
    details_json: dict[str, Any] = Field(default_factory=dict)

    @field_validator("title")
    @classmethod
    def validate_title(cls, value: str) -> str:
        cleaned = sanitize_text(value)
        if not cleaned:
            raise ValueError("title must not be empty")
        return cleaned

    @field_validator("details_json", mode="before")
    @classmethod
    def validate_details(cls, value: Any) -> dict[str, Any]:
        return sanitize_json_object(value)


class EventBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[EventEnvelope] = Field(default_factory=list, min_length=1, max_length=MAX_EVENTS_PER_BATCH)


class IngestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    org_id: str = Field(min_length=1, max_length=256)
    device_id: str = Field(min_length=1, max_length=256)
    agent_version: str = Field(min_length=1, max_length=64)
    sent_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    nonce: str = Field(min_length=NONCE_MIN_LENGTH, max_length=NONCE_MAX_LENGTH)
    events: list[EventEnvelope] = Field(default_factory=list, min_length=1, max_length=MAX_EVENTS_PER_BATCH)

    @field_validator("org_id", "device_id", "agent_version", "nonce")
    @classmethod
    def sanitize_scalar(cls, value: str) -> str:
        cleaned = sanitize_text(value)
        if not cleaned:
            raise ValueError("field cannot be empty")
        return cleaned

    @model_validator(mode="after")
    def validate_events(self) -> "IngestRequest":
        if len(self.events) > MAX_EVENTS_PER_BATCH:
            raise ValueError(f"events exceeds max {MAX_EVENTS_PER_BATCH}")
        return self


class IngestResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    accepted: int = Field(ge=0)
    rejected: int = Field(ge=0)
    server_time: datetime = Field(default_factory=lambda: datetime.now(UTC))
