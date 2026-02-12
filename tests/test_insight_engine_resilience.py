from __future__ import annotations

from datetime import UTC, datetime

import pytest

from core.engine import build_insight_bundle


def test_build_insight_bundle_requires_events() -> None:
    with pytest.raises(ValueError):
        build_insight_bundle([], now=datetime.now(UTC))
