from __future__ import annotations

import os
from pathlib import Path

from agent.collectors.base import Collector
from agent.collectors.common import (
    FilewatchCollector,
    NetworkCollector,
    PersistenceCollector,
    ProcessCollector,
    ScheduledTaskCollector,
)
from agent.config import AgentConfig, default_agent_dir
from agent.platforms.macos import MacOSAuthCollector
from agent.platforms.windows import WindowsAuthCollector
from shared.enums import Platform


def current_platform() -> Platform:
    if os.name == "nt":
        return Platform.WINDOWS
    return Platform.MACOS


def build_collectors(config: AgentConfig) -> list[Collector]:
    platform = current_platform()
    collectors: list[Collector] = [
        ProcessCollector(
            platform=platform,
            deny_process_names=config.deny_process_names,
            unusual_exec_paths=config.unusual_exec_paths,
            max_events=min(150, config.max_batch_events),
        ),
        NetworkCollector(platform=platform, max_events=min(120, config.max_batch_events)),
        PersistenceCollector(platform=platform, max_events=80),
        ScheduledTaskCollector(platform=platform, max_events=80),
    ]

    if platform == Platform.MACOS:
        collectors.append(MacOSAuthCollector(max_events=50))
    else:
        collectors.append(WindowsAuthCollector(max_events=50))

    if config.enable_filewatch:
        state_path = Path(default_agent_dir()) / "filewatch_state.json"
        collectors.append(
            FilewatchCollector(
                platform=platform,
                watch_paths=config.watch_paths,
                state_path=state_path,
                max_events=min(100, config.max_batch_events),
            )
        )
    return collectors
