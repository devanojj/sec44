from __future__ import annotations

from pathlib import Path

import pytest

from mac_watchdog.config import load_config


BASE_CONFIG = """interval_seconds = 60
web_host = \"127.0.0.1\"
web_port = 8765
enable_file_watch = false
watch_paths = [\"~/Downloads\", \"~/Desktop\"]
deny_process_names = []
allow_process_paths = []
unusual_exec_paths = [\"/tmp\", \"/private/tmp\"]
severity_weights = { INFO = 1, WARN = 3, HIGH = 8 }
dev_enable_docs = false
"""


def test_config_rejects_unknown_keys(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(BASE_CONFIG + "unexpected = 1\n", encoding="utf-8")

    with pytest.raises(ValueError):
        load_config(config_path)


def test_config_rejects_invalid_type(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(BASE_CONFIG.replace("interval_seconds = 60", "interval_seconds = \"x\""), encoding="utf-8")

    with pytest.raises(ValueError):
        load_config(config_path)


def test_config_loads_valid_file(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(BASE_CONFIG, encoding="utf-8")

    cfg = load_config(config_path)
    assert cfg.interval_seconds == 60
    assert cfg.web_host == "127.0.0.1"
    assert cfg.data_dir == tmp_path
    assert cfg.db_path == tmp_path / "mac_watchdog.db"
