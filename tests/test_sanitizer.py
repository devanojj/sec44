from __future__ import annotations

from mac_watchdog.sanitizer import MAX_FIELD_LEN, safe_json_dumps, sanitize_text


def test_sanitize_text_removes_control_chars_and_truncates() -> None:
    raw = "hello\x00world\x1f" + ("x" * (MAX_FIELD_LEN + 5))
    out = sanitize_text(raw)
    assert "\x00" not in out
    assert "\x1f" not in out
    assert len(out) == MAX_FIELD_LEN


def test_safe_json_dumps_handles_non_json_types() -> None:
    payload = {"a": "ok\x00", "b": b"bytes\x01"}
    dumped = safe_json_dumps(payload)
    assert "\\u0000" not in dumped
    assert "bytes" in dumped
