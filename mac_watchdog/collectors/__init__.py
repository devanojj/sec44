"""Collectors for local security signals."""

from .filewatch import FileWatchService
from .logins import collect_login_events
from .network import collect_network_events
from .processes import collect_process_events

__all__ = [
    "FileWatchService",
    "collect_process_events",
    "collect_login_events",
    "collect_network_events",
]
