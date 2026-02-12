from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    org_id: str = Field(min_length=1, max_length=256)
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=8, max_length=256)

    @field_validator("org_id", "username")
    @classmethod
    def normalize(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("empty value")
        return cleaned


class TokenPair(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = Field(ge=1)


class MetricsQuery(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    org_id: str = Field(min_length=1, max_length=256)
    device_id: str | None = Field(default=None, max_length=256)
    page: int = Field(default=1, ge=1, le=100000)
    page_size: int = Field(default=25, ge=1, le=200)


class Principal(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    user_id: int = Field(ge=1)
    org_id: str
    username: str
    role: str


class CreateUserRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    org_id: str = Field(min_length=1, max_length=256)
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=8, max_length=256)
    role: str = Field(default="read_only")


class RefreshRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    refresh_token: str = Field(min_length=20, max_length=4096)


class ErrorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    detail: str
    server_time: datetime = Field(default_factory=lambda: datetime.now(UTC))
