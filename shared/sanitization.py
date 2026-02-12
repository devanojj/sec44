from __future__ import annotations

import re
from typing import Any

from shared.constants import MAX_STRING_LEN

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


def sanitize_text(value: Any, max_len: int = MAX_STRING_LEN) -> str:
    text = str(value)
    text = _CONTROL_RE.sub("", text)
    text = _EMAIL_RE.sub("[email-redacted]", text)
    if len(text) > max_len:
        return text[:max_len]
    return text


def sanitize_json(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            cleaned[sanitize_text(key)] = sanitize_json(item)
        return cleaned
    if isinstance(value, list):
        return [sanitize_json(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize_json(item) for item in value]
    if isinstance(value, str):
        return sanitize_text(value)
    if isinstance(value, bytes):
        return sanitize_text(value.decode("utf-8", errors="replace"))
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return sanitize_text(value)


def sanitize_json_object(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("details_json must be a JSON object")
    cleaned = sanitize_json(value)
    if not isinstance(cleaned, dict):
        raise ValueError("details_json must be a JSON object")
    return cleaned
