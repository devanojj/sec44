from __future__ import annotations

import argparse
import logging
import signal
import threading
from pathlib import Path

from agent.config import default_config_path, default_spool_path, init_config, load_config
from agent.runtime import run_daemon, run_once

logger = logging.getLogger("endpoint_agent")


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s %(message)s")


def cmd_init(args: argparse.Namespace) -> int:
    path = init_config(Path(args.config).expanduser() if args.config else None)
    print(f"initialized config: {path}")
    print(f"spool database: {default_spool_path()}")
    return 0


def cmd_run_once(args: argparse.Namespace) -> int:
    config = load_config(Path(args.config).expanduser() if args.config else None)
    summary = run_once(config, spool_path=default_spool_path())
    print(summary)
    return 0


def cmd_daemon(args: argparse.Namespace) -> int:
    config = load_config(Path(args.config).expanduser() if args.config else None)
    stop_event = threading.Event()

    def _stop(signum: int, frame: object) -> None:
        del frame
        logger.info("received signal %s", signum)
        stop_event.set()

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    run_daemon(config, stop_event=stop_event, spool_path=default_spool_path())
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent")
    parser.add_argument("--verbose", action="store_true")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="initialize local agent config")
    init_parser.add_argument("--config", type=str, default=str(default_config_path()))
    init_parser.set_defaults(func=cmd_init)

    run_once_parser = subparsers.add_parser("run-once", help="collect once and send to server")
    run_once_parser.add_argument("--config", type=str, default=str(default_config_path()))
    run_once_parser.set_defaults(func=cmd_run_once)

    daemon_parser = subparsers.add_parser("daemon", help="run continuous collection")
    daemon_parser.add_argument("--config", type=str, default=str(default_config_path()))
    daemon_parser.set_defaults(func=cmd_daemon)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _configure_logging(bool(args.verbose))
    return int(args.func(args))
