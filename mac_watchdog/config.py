from __future__ import annotations

import ipaddress
import os
import stat
import tomllib
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, ValidationError, field_validator

DEFAULT_DATA_DIR = Path.home() / ".mac_watchdog"
DEFAULT_CONFIG_PATH = DEFAULT_DATA_DIR / "config.toml"
DEFAULT_DB_PATH = DEFAULT_DATA_DIR / "mac_watchdog.db"


class AppConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    _data_dir: Path = PrivateAttr(default=DEFAULT_DATA_DIR)
    _db_path: Path = PrivateAttr(default=DEFAULT_DB_PATH)

    interval_seconds: int = Field(default=60, ge=5, le=3600)
    web_host: str = "127.0.0.1"
    web_port: int = Field(default=8765, ge=1, le=65535)
    enable_file_watch: bool = False
    watch_paths: list[str] = Field(default_factory=lambda: ["~/Downloads", "~/Desktop"])
    deny_process_names: list[str] = Field(default_factory=list)
    allow_process_paths: list[str] = Field(default_factory=list)
    unusual_exec_paths: list[str] = Field(default_factory=lambda: ["/tmp", "/private/tmp"])
    severity_weights: dict[str, int] = Field(
        default_factory=lambda: {"INFO": 1, "WARN": 3, "HIGH": 8}
    )
    dev_enable_docs: bool = False

    @field_validator("web_host")
    @classmethod
    def validate_localhost_only(cls, value: str) -> str:
        host = value.strip()
        if host == "localhost":
            return host
        try:
            ip = ipaddress.ip_address(host)
        except ValueError as exc:
            raise ValueError("web_host must be localhost or a loopback IP") from exc
        if not ip.is_loopback:
            raise ValueError("web_host must be a loopback address for local-only MVP")
        return host

    @field_validator("watch_paths", mode="before")
    @classmethod
    def normalize_watch_paths(cls, value: Any) -> Any:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("deny_process_names", "allow_process_paths", "unusual_exec_paths", mode="before")
    @classmethod
    def normalize_string_list(cls, value: Any) -> Any:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("watch_paths")
    @classmethod
    def validate_watch_paths(cls, value: list[str]) -> list[str]:
        home = Path.home().resolve()
        normalized: list[str] = []
        for entry in value:
            resolved = Path(entry).expanduser().resolve(strict=False)
            try:
                common = Path(os.path.commonpath([str(home), str(resolved)]))
            except ValueError as exc:
                raise ValueError(f"watch path {entry!r} is invalid") from exc
            if common != home:
                raise ValueError(f"watch path {entry!r} must be under the user home directory")
            normalized.append(str(resolved))
        return normalized

    @field_validator("allow_process_paths", "unusual_exec_paths")
    @classmethod
    def normalize_paths(cls, value: list[str]) -> list[str]:
        return [str(Path(item).expanduser().resolve(strict=False)) for item in value]

    @field_validator("severity_weights")
    @classmethod
    def validate_weights(cls, value: dict[str, int]) -> dict[str, int]:
        expected = {"INFO", "WARN", "HIGH"}
        if set(value.keys()) != expected:
            raise ValueError("severity_weights must contain exactly INFO, WARN, HIGH")
        for key, weight in value.items():
            if weight < 0:
                raise ValueError(f"severity weight for {key} must be >= 0")
        return value

    @property
    def data_dir(self) -> Path:
        return self._data_dir

    @property
    def db_path(self) -> Path:
        return self._db_path


def _parse_bool(raw: str) -> bool:
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"invalid boolean: {raw}")


def _parse_weights(raw: str) -> dict[str, int]:
    parts = [chunk.strip() for chunk in raw.split(",") if chunk.strip()]
    parsed: dict[str, int] = {}
    for part in parts:
        key, sep, value = part.partition("=")
        if sep != "=":
            raise ValueError("MAC_WATCHDOG_SEVERITY_WEIGHTS must look like INFO=1,WARN=3,HIGH=8")
        parsed[key.strip().upper()] = int(value.strip())
    return parsed


def _env_overrides() -> dict[str, Any]:
    mapping: dict[str, tuple[str, str]] = {
        "MAC_WATCHDOG_INTERVAL": ("interval_seconds", "int"),
        "MAC_WATCHDOG_HOST": ("web_host", "str"),
        "MAC_WATCHDOG_PORT": ("web_port", "int"),
        "MAC_WATCHDOG_ENABLE_FILE_WATCH": ("enable_file_watch", "bool"),
        "MAC_WATCHDOG_WATCH_PATHS": ("watch_paths", "list"),
        "MAC_WATCHDOG_DENY_PROCESS_NAMES": ("deny_process_names", "list"),
        "MAC_WATCHDOG_ALLOW_PROCESS_PATHS": ("allow_process_paths", "list"),
        "MAC_WATCHDOG_UNUSUAL_EXEC_PATHS": ("unusual_exec_paths", "list"),
        "MAC_WATCHDOG_DEV_ENABLE_DOCS": ("dev_enable_docs", "bool"),
        "MAC_WATCHDOG_SEVERITY_WEIGHTS": ("severity_weights", "weights"),
    }
    out: dict[str, Any] = {}
    for env_name, (field_name, kind) in mapping.items():
        raw = os.getenv(env_name)
        if raw is None:
            continue
        if kind == "int":
            out[field_name] = int(raw)
        elif kind == "bool":
            out[field_name] = _parse_bool(raw)
        elif kind == "list":
            out[field_name] = [item.strip() for item in raw.split(",") if item.strip()]
        elif kind == "weights":
            out[field_name] = _parse_weights(raw)
        else:
            out[field_name] = raw
    return out


def secure_path(path: Path, mode: int) -> None:
    path.chmod(mode)
    actual = stat.S_IMODE(path.stat().st_mode)
    if actual != mode:
        raise PermissionError(f"failed to enforce permissions {oct(mode)} on {path}")


def default_config_toml() -> str:
    return """interval_seconds = 60
web_host = \"127.0.0.1\"
web_port = 8765
enable_file_watch = false
watch_paths = [\"~/Downloads\", \"~/Desktop\"]
deny_process_names = []
allow_process_paths = []
unusual_exec_paths = [\"/tmp\", \"/private/tmp\"]
severity_weights = { INFO = 1, WARN = 3, HIGH = 8 }
dev_enable_docs = false
"""


def ensure_app_paths(config_path: Path = DEFAULT_CONFIG_PATH) -> None:
    data_dir = config_path.expanduser().resolve(strict=False).parent
    if data_dir.exists() and data_dir.is_symlink():
        raise ValueError(f"refusing symlinked data directory: {data_dir}")
    data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    secure_path(data_dir, 0o700)

    if config_path.exists() and config_path.is_symlink():
        raise ValueError(f"refusing symlinked config file: {config_path}")
    if not config_path.exists():
        config_path.write_text(default_config_toml(), encoding="utf-8")
    secure_path(config_path, 0o600)


def load_config(config_path: Path | None = None) -> AppConfig:
    path = (config_path or DEFAULT_CONFIG_PATH).expanduser().resolve(strict=False)
    ensure_app_paths(path)
    parsed: dict[str, Any]
    with path.open("rb") as handle:
        parsed = tomllib.load(handle)
    parsed.update(_env_overrides())
    try:
        config = AppConfig.model_validate(parsed)
    except ValidationError as exc:
        raise ValueError(f"invalid config at {path}: {exc}") from exc
    config._data_dir = path.parent
    config._db_path = path.parent / "mac_watchdog.db"
    return config
