from __future__ import annotations

from typing import Protocol

from shared.schemas import EventEnvelope


class Collector(Protocol):
    def collect(self) -> list[EventEnvelope]:
        """Collect and normalize endpoint events."""
