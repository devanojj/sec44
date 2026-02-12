from __future__ import annotations

from shared.sanitization import sanitize_text


def test_sanitize_removes_controls_and_redacts_email() -> None:
    raw = "hello\x00world user@example.com"
    out = sanitize_text(raw)
    assert "\x00" not in out
    assert "user@example.com" not in out
    assert "[email-redacted]" in out
