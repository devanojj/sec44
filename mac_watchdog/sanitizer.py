from __future__ import annotations

import json
import re
from typing import Any

MAX_FIELD_LEN = 4096
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_text(value: Any, max_len: int = MAX_FIELD_LEN) -> str:
    text = str(value)
    text = _CONTROL_RE.sub("", text)
    if len(text) > max_len:
        return text[:max_len]
    return text


def sanitize_jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {sanitize_text(key): sanitize_jsonable(item) for key, item in value.items()}
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
