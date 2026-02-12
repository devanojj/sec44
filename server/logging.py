from __future__ import annotations

import json
import logging
import os
from datetime import UTC, datetime
from typing import Any

_SENSITIVE_KEYS = {
    "api_key",
    "api_key_hash",
    "authorization",
    "password",
    "password_hash",
    "secret",
    "token",
    "jwt",
}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        for key, value in record.__dict__.items():
            if key.startswith("_") or key in {
                "msg",
                "args",
                "name",
                "levelname",
                "levelno",
                "pathname",
                "filename",
                "module",
                "exc_info",
                "exc_text",
                "stack_info",
                "lineno",
                "funcName",
                "created",
                "msecs",
                "relativeCreated",
                "thread",
                "threadName",
                "processName",
                "process",
                "message",
            }:
                continue
            lowered = key.lower()
            if any(secret in lowered for secret in _SENSITIVE_KEYS):
                payload[key] = "[REDACTED]"
            else:
                payload[key] = value
        return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))


def configure_logging(verbose: bool = False) -> None:
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)

    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler()

    if os.getenv("EM_LOG_FORMAT", "json").lower() == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))

    root.setLevel(level)
    root.addHandler(handler)
