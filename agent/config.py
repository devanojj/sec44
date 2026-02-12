from __future__ import annotations

import os
import stat
try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - only for Python < 3.11
    import tomli as tomllib  # type: ignore[import-not-found]
import uuid
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from shared.constants import MAX_EVENTS_PER_BATCH


class AgentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    server_url: str = "http://127.0.0.1:8000"
    org_id: str = "dev-org"
    device_id: str
    api_key: str | None = None
    agent_version: str = "0.2.0"
    interval_seconds: int = Field(default=60, ge=5, le=3600)
    enable_filewatch: bool = False
    watch_paths: list[str] = Field(default_factory=lambda: [str(Path.home() / "Downloads")])
    deny_process_names: list[str] = Field(default_factory=list)
    unusual_exec_paths: list[str] = Field(
        default_factory=lambda: ["/tmp", "/private/tmp", "\\AppData\\Local\\Temp", "\\Temp"]
    )
    tls_verify: bool = True
    timeout_seconds: int = Field(default=10, ge=3, le=60)
    max_batch_events: int = Field(default=MAX_EVENTS_PER_BATCH, ge=1, le=MAX_EVENTS_PER_BATCH)
    spool_max_batches: int = Field(default=1000, ge=10, le=10000)
    platform: dict[str, Any] = Field(default_factory=lambda: {"failed_login_spike_threshold": 5})

    @field_validator("server_url", "org_id", "device_id", "agent_version")
    @classmethod
    def validate_non_empty(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("field cannot be empty")
        return cleaned


def default_agent_dir() -> Path:
    if os.name == "nt":
        appdata = os.getenv("APPDATA")
        base = Path(appdata) if appdata else Path.home() / "AppData" / "Roaming"
        return base / "EndpointMonitorAgent"
    return Path.home() / ".endpoint_monitor_agent"


def default_config_path() -> Path:
    return default_agent_dir() / "config.toml"


def default_spool_path() -> Path:
    return default_agent_dir() / "spool.db"


def _secure_path(path: Path, mode: int) -> None:
    if os.name == "nt":
        return
    path.chmod(mode)
    actual = stat.S_IMODE(path.stat().st_mode)
    if actual != mode:
        raise PermissionError(f"unable to set permissions {oct(mode)} for {path}")


def ensure_agent_dir(path: Path | None = None) -> Path:
    target = path or default_agent_dir()
    target.mkdir(parents=True, exist_ok=True)
    _secure_path(target, 0o700)
    return target


def default_config_text(device_id: str) -> str:
    return (
        f'server_url = "http://127.0.0.1:8000"\n'
        f'org_id = "dev-org"\n'
        f'device_id = "{device_id}"\n'
        "api_key = \"\"\n"
        "agent_version = \"0.2.0\"\n"
        "interval_seconds = 60\n"
        "enable_filewatch = false\n"
        f'watch_paths = ["{str(Path.home() / "Downloads")}"]\n'
        "deny_process_names = []\n"
        "unusual_exec_paths = [\"/tmp\", \"/private/tmp\", \"\\\\AppData\\\\Local\\\\Temp\", \"\\\\Temp\"]\n"
        "tls_verify = true\n"
        "timeout_seconds = 10\n"
        f"max_batch_events = {MAX_EVENTS_PER_BATCH}\n"
        "spool_max_batches = 1000\n"
        "platform = { failed_login_spike_threshold = 5 }\n"
    )


def init_config(config_path: Path | None = None) -> Path:
    path = (config_path or default_config_path()).expanduser().resolve(strict=False)
    directory = ensure_agent_dir(path.parent)
    del directory
    if path.exists():
        _secure_path(path, 0o600)
        return path
    device_id = str(uuid.uuid4())
    path.write_text(default_config_text(device_id), encoding="utf-8")
    _secure_path(path, 0o600)
    return path


def load_config(config_path: Path | None = None) -> AgentConfig:
    path = init_config(config_path)
    with path.open("rb") as handle:
        raw: dict[str, Any] = tomllib.load(handle)

    env_api_key = os.getenv("EM_AGENT_API_KEY")
    if env_api_key:
        raw["api_key"] = env_api_key

    config = AgentConfig.model_validate(raw)
    if not config.api_key:
        raise ValueError("agent api_key is required; set api_key in config.toml or EM_AGENT_API_KEY")

    if config.server_url.startswith("http://") and config.tls_verify:
        # Development convenience while still warning loudly.
        print("WARNING: using HTTP transport; production deployment must use HTTPS.")
    return config
