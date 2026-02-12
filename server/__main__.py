from __future__ import annotations

import argparse
import json
import secrets

import uvicorn
from alembic import command
from alembic.config import Config

from server.app import create_app
from server.config import OrgSeed, UserSeed, load_config
from server.db import ServerDatabase
from server.logging import configure_logging


def cmd_run(args: argparse.Namespace) -> int:
    cfg = load_config()
    app = create_app(cfg)
    uvicorn.run(app, host=cfg.host, port=cfg.port, log_level="debug" if args.verbose else "info")
    return 0


def cmd_migrate(args: argparse.Namespace) -> int:
    cfg = load_config()
    alembic_cfg = Config("alembic.ini")
    alembic_cfg.set_main_option("sqlalchemy.url", cfg.database_url)
    command.upgrade(alembic_cfg, args.revision)
    return 0


def cmd_create_org(args: argparse.Namespace) -> int:
    cfg = load_config()
    db = ServerDatabase(cfg.database_url)
    api_key = args.api_key or secrets.token_urlsafe(32)
    seed = OrgSeed(
        org_id=args.org_id,
        org_name=args.org_name,
        api_key=api_key,
        ingest_rate_limit_per_minute=int(args.rate_limit),
    )
    db.seed_orgs([seed])

    output = {
        args.org_id: {
            "name": args.org_name,
            "api_key": api_key,
            "rate_limit_per_minute": int(args.rate_limit),
        }
    }
    print(json.dumps(output, ensure_ascii=True))
    return 0


def cmd_create_user(args: argparse.Namespace) -> int:
    cfg = load_config()
    db = ServerDatabase(cfg.database_url)
    from server.auth import AuthManager

    auth = AuthManager(cfg)
    db.seed_users(
        [
            UserSeed(
                org_id=args.org_id,
                username=args.username,
                password=args.password,
                role=args.role,
            )
        ],
        auth.hash_password,
    )
    print("user upserted")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="server")
    parser.add_argument("--verbose", action="store_true")
    subparsers = parser.add_subparsers(dest="command")

    run_parser = subparsers.add_parser("run", help="run the FastAPI server")
    run_parser.set_defaults(func=cmd_run)

    migrate_parser = subparsers.add_parser("migrate", help="run Alembic migration")
    migrate_parser.add_argument("--revision", default="head")
    migrate_parser.set_defaults(func=cmd_migrate)

    org_parser = subparsers.add_parser("create-org", help="create org record")
    org_parser.add_argument("--org-id", required=True)
    org_parser.add_argument("--org-name", required=True)
    org_parser.add_argument("--api-key", default=None)
    org_parser.add_argument("--rate-limit", default="60")
    org_parser.set_defaults(func=cmd_create_org)

    user_parser = subparsers.add_parser("create-user", help="create dashboard user")
    user_parser.add_argument("--org-id", required=True)
    user_parser.add_argument("--username", required=True)
    user_parser.add_argument("--password", required=True)
    user_parser.add_argument("--role", choices=["admin", "read_only"], default="read_only")
    user_parser.set_defaults(func=cmd_create_user)

    parser.set_defaults(func=cmd_run)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(verbose=bool(args.verbose))
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
