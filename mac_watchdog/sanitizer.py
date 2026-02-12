from __future__ import annotations

import json
import re
from typing import Any

MAX_FIELD_LEN = 4096
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SECRET_KEY_RE = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|authorization|bearer|session|cookie)",
    re.IGNORECASE,
)
_SECRET_VALUE_RE = re.compile(
    r"(bearer\s+[a-z0-9._\-]{12,}|"
    r"(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*[^,\s]+|"
    r"[a-z0-9_\-]{24,}\.[a-z0-9_\-]{10,}\.[a-z0-9_\-]{10,})",
    re.IGNORECASE,
)
REDACTED = "[REDACTED]"


def _is_secret_key(value: str) -> bool:
    return bool(_SECRET_KEY_RE.search(value))


def _redact_secret_like(value: str) -> str:
    if _SECRET_VALUE_RE.search(value):
        return _SECRET_VALUE_RE.sub(REDACTED, value)
    return value


def sanitize_text(value: Any, max_len: int = MAX_FIELD_LEN) -> str:
    text = str(value)
    text = _redact_secret_like(text)
    text = _CONTROL_RE.sub("", text)
    if len(text) > max_len:
        return text[:max_len]
    return text


def sanitize_jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            key_text = sanitize_text(key)
            if _is_secret_key(key_text):
                cleaned[key_text] = REDACTED
            else:
                cleaned[key_text] = sanitize_jsonable(item)
        return cleaned
    if isinstance(value, list):
        return [sanitize_jsonable(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize_jsonable(item) for item in value]
    if isinstance(value, bytes):
        return sanitize_text(value.decode("utf-8", errors="replace"))
    if isinstance(value, (str, int, float, bool)) or value is None:
        return sanitize_text(value) if isinstance(value, str) else value
    return sanitize_text(value)


def safe_json_dumps(value: Any) -> str:
    cleaned = sanitize_jsonable(value)
    return json.dumps(cleaned, ensure_ascii=True, separators=(",", ":"))
