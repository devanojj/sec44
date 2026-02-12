from __future__ import annotations

from enum import Enum


class Source(str, Enum):
    PROCESS = "process"
    AUTH = "auth"
    NETWORK = "network"
    FILEWATCH = "filewatch"
    SYSTEM = "system"


class Severity(str, Enum):
    INFO = "INFO"
    WARN = "WARN"
    HIGH = "HIGH"


class Platform(str, Enum):
    MACOS = "macos"
    WINDOWS = "windows"
