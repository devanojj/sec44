from __future__ import annotations

import argparse
import logging
import signal
import threading
from pathlib import Path
from typing import Any

import uvicorn

from mac_watchdog.config import DEFAULT_CONFIG_PATH, AppConfig, ensure_app_paths, load_config
from mac_watchdog.db import Database
from mac_watchdog.scheduler import WatchdogScheduler
from mac_watchdog.web.app import create_app

logger = logging.getLogger("mac_watchdog")


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s %(message)s")


def _apply_cli_overrides(config: AppConfig, args: argparse.Namespace) -> AppConfig:
    updates: dict[str, Any] = {}
    if getattr(args, "interval", None) is not None:
        updates["interval_seconds"] = int(args.interval)
    if getattr(args, "host", None) is not None:
        updates["web_host"] = str(args.host)
    if getattr(args, "port", None) is not None:
        updates["web_port"] = int(args.port)
    if not updates:
        return config
    merged = config.model_dump()
    merged.update(updates)
    return AppConfig.model_validate(merged)


def _load(config_path: str | None) -> AppConfig:
    path = Path(config_path).expanduser() if config_path else DEFAULT_CONFIG_PATH
    ensure_app_paths(path)
    return load_config(path)


def cmd_init(args: argparse.Namespace) -> int:
    config = _load(args.config)
    db = Database(config.db_path)
    db.close()
    logger.info("initialized config at %s", Path(args.config).expanduser() if args.config else DEFAULT_CONFIG_PATH)
    logger.info("initialized database at %s", config.db_path)
    return 0


def cmd_run_once(args: argparse.Namespace) -> int:
    config = _load(args.config)
    config = _apply_cli_overrides(config, args)

    db = Database(config.db_path)
    try:
        scheduler = WatchdogScheduler(config=config, db=db, verbose=args.verbose)
        summary = scheduler.run_once()
        logger.info("run-once summary: %s", summary)
    finally:
        db.close()
    return 0


def _register_signal_handlers(stop_event: threading.Event, server: uvicorn.Server | None = None) -> None:
    def _handler(signum: int, frame: Any) -> None:
        del frame
        logger.info("received signal %s, shutting down", signum)
        stop_event.set()
        if server is not None:
            server.should_exit = True

    signal.signal(signal.SIGINT, _handler)
    signal.signal(signal.SIGTERM, _handler)


def cmd_daemon(args: argparse.Namespace) -> int:
    config = _load(args.config)
    config = _apply_cli_overrides(config, args)

    db = Database(config.db_path)
    scheduler = WatchdogScheduler(config=config, db=db, verbose=args.verbose)
    stop_event = threading.Event()

    try:
        if args.no_web:
            _register_signal_handlers(stop_event)
            scheduler.run_daemon(stop_event)
            return 0

        scheduler_thread = threading.Thread(target=scheduler.run_daemon, args=(stop_event,), daemon=True)
        scheduler_thread.start()

        app = create_app(config, db)
        uv_config = uvicorn.Config(
            app,
            host=config.web_host,
            port=config.web_port,
            log_level="debug" if args.verbose else "info",
        )
        server = uvicorn.Server(uv_config)
        _register_signal_handlers(stop_event, server)

        server.run()
        stop_event.set()
        scheduler_thread.join(timeout=5)
        return 0
    finally:
        db.close()


def cmd_serve(args: argparse.Namespace) -> int:
    config = _load(args.config)
    config = _apply_cli_overrides(config, args)

    db = Database(config.db_path)
    app = create_app(config, db)
    try:
        uvicorn.run(
            app,
            host=config.web_host,
            port=config.web_port,
            log_level="debug" if args.verbose else "info",
        )
        return 0
    finally:
        db.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mac-watchdog")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="create config, data dir, and SQLite database")
    init_parser.add_argument("--config", type=str, default=None, help="path to config.toml")
    init_parser.set_defaults(func=cmd_init)

    once_parser = subparsers.add_parser("run-once", help="run collectors once")
    once_parser.add_argument("--config", type=str, default=None, help="path to config.toml")
    once_parser.add_argument("--verbose", action="store_true")
    once_parser.set_defaults(func=cmd_run_once)

    daemon_parser = subparsers.add_parser("daemon", help="run collectors periodically")
    daemon_parser.add_argument("--config", type=str, default=None, help="path to config.toml")
    daemon_parser.add_argument("--interval", type=int, default=None, help="collector interval override")
    daemon_parser.add_argument("--no-web", action="store_true", help="disable local web server")
    daemon_parser.add_argument("--verbose", action="store_true")
    daemon_parser.set_defaults(func=cmd_daemon)

    serve_parser = subparsers.add_parser("serve", help="serve local web dashboard only")
    serve_parser.add_argument("--config", type=str, default=None, help="path to config.toml")
    serve_parser.add_argument("--host", type=str, default="127.0.0.1", help="bind host")
    serve_parser.add_argument("--port", type=int, default=8765, help="bind port")
    serve_parser.add_argument("--verbose", action="store_true")
    serve_parser.set_defaults(func=cmd_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _configure_logging(bool(getattr(args, "verbose", False)))
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
