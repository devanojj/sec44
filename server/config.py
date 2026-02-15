from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class OrgSeed:
    org_id: str
    org_name: str
    api_key: str
    ingest_rate_limit_per_minute: int


@dataclass(frozen=True, slots=True)
class UserSeed:
    org_id: str
    username: str
    password: str
    role: str


@dataclass(frozen=True, slots=True)
class ServerConfig:
    environment: str
    database_url: str
    redis_url: str
    host: str
    port: int
    dev_enable_docs: bool
    enforce_https: bool
    replay_window_seconds: int
    max_ingest_compute_seconds: int
    max_payload_bytes: int
    jwt_access_secret: str
    jwt_refresh_secret: str
    jwt_issuer: str
    jwt_audience: str
    access_token_ttl_seconds: int
    refresh_token_ttl_seconds: int
    metrics_token: str | None
    csrf_secret: str
    org_seeds: list[OrgSeed]
    user_seeds: list[UserSeed]


def _require_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise ValueError(f"{name} is required")
    return value


def _parse_bool(raw: str | None, default: bool) -> bool:
    if raw is None:
        return default
    lowered = raw.strip().lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    return default


def _parse_org_seeds() -> list[OrgSeed]:
    raw = _require_env("EM_ORGS_JSON")
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("EM_ORGS_JSON must be a JSON object")

    output: list[OrgSeed] = []
    for org_id, value in parsed.items():
        if not isinstance(value, dict):
            continue
        api_key = str(value.get("api_key") or "").strip()
        if not api_key:
            continue
        org_name = str(value.get("name") or org_id).strip()
        rate_limit = int(value.get("rate_limit_per_minute") or 60)
        output.append(
            OrgSeed(
                org_id=str(org_id).strip(),
                org_name=org_name,
                api_key=api_key,
                ingest_rate_limit_per_minute=max(1, min(rate_limit, 10000)),
            )
        )

    if not output:
        raise ValueError("EM_ORGS_JSON contains no usable org records")
    return output


def _parse_user_seeds() -> list[UserSeed]:
    raw = os.getenv("EM_USERS_JSON", "").strip()
    if not raw:
        return []
    parsed = json.loads(raw)
    if not isinstance(parsed, list):
        raise ValueError("EM_USERS_JSON must be a JSON array")

    output: list[UserSeed] = []
    for item in parsed:
        if not isinstance(item, dict):
            continue
        org_id = str(item.get("org_id") or "").strip()
        username = str(item.get("username") or "").strip()
        password = str(item.get("password") or "").strip()
        role = str(item.get("role") or "read_only").strip()
        if not org_id or not username or not password:
            continue
        if role not in {"admin", "read_only"}:
            role = "read_only"
        output.append(UserSeed(org_id=org_id, username=username, password=password, role=role))
    return output


def _validate_database_url(url: str, allow_test_sqlite: bool) -> str:
    lowered = url.lower()
    if lowered.startswith("postgresql://") or lowered.startswith("postgresql+psycopg://"):
        return url
    if allow_test_sqlite and lowered.startswith("sqlite://"):
        return url
    raise ValueError("DATABASE_URL must use PostgreSQL in non-test deployments")


def load_config() -> ServerConfig:
    environment = os.getenv("EM_ENV", "development").strip().lower()
    allow_test_sqlite = _parse_bool(os.getenv("EM_ALLOW_SQLITE_FOR_TESTS"), environment in {"test", "ci"})

    database_url_from_env = os.getenv("DATABASE_URL", "").strip()
    if not database_url_from_env and (os.getenv("CI") or os.getenv("RAILWAY_STATIC_URL")):
        # If DATABASE_URL is not set and we are in a CI/build environment,
        # provide a dummy URL to allow configuration loading to proceed.
        # The real DATABASE_URL will be provided at runtime by Railway.
        print("WARNING: Using dummy DATABASE_URL for build process.")
        database_url_from_env = "postgresql+psycopg://dummy:dummy@localhost/dummy"
    elif not database_url_from_env:
        # If DATABASE_URL is genuinely missing in a non-build environment,
        # then it's a real error.
        raise ValueError("DATABASE_URL is required")

    database_url = _validate_database_url(database_url_from_env, allow_test_sqlite=allow_test_sqlite)
    redis_url = _require_env("REDIS_URL")

    dev_docs_flag = _parse_bool(os.getenv("EM_DEV_ENABLE_DOCS"), False)
    dev_enable_docs = bool(dev_docs_flag and environment in {"development", "local", "dev", "test", "ci"})

    enforce_https_default = environment in {"production", "prod", "staging"}
    enforce_https = _parse_bool(os.getenv("EM_ENFORCE_HTTPS"), enforce_https_default)

    return ServerConfig(
        environment=environment,
        database_url=database_url,
        redis_url=redis_url,
        host=os.getenv("EM_SERVER_HOST", "0.0.0.0"),
        port=int(os.getenv("EM_SERVER_PORT", "8000")),
        dev_enable_docs=dev_enable_docs,
        enforce_https=enforce_https,
        replay_window_seconds=int(os.getenv("EM_REPLAY_WINDOW_SECONDS", "300")),
        max_ingest_compute_seconds=int(os.getenv("EM_MAX_INGEST_COMPUTE_SECONDS", "3")),
        max_payload_bytes=int(os.getenv("EM_MAX_PAYLOAD_BYTES", str(512 * 1024))),
        jwt_access_secret=_require_env("EM_JWT_ACCESS_SECRET"),
        jwt_refresh_secret=_require_env("EM_JWT_REFRESH_SECRET"),
        jwt_issuer=os.getenv("EM_JWT_ISSUER", "endpoint-monitor"),
        jwt_audience=os.getenv("EM_JWT_AUDIENCE", "endpoint-monitor-users"),
        access_token_ttl_seconds=int(os.getenv("EM_ACCESS_TOKEN_TTL_SECONDS", "900")),
        refresh_token_ttl_seconds=int(os.getenv("EM_REFRESH_TOKEN_TTL_SECONDS", "259200")),
        metrics_token=os.getenv("EM_METRICS_TOKEN", "").strip() or None,
        csrf_secret=_require_env("EM_CSRF_SECRET"),
        org_seeds=_parse_org_seeds(),
        user_seeds=_parse_user_seeds(),
    )
