from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from server.models import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)


target_metadata = Base.metadata


def _database_url() -> str:
    env_url = os.getenv("DATABASE_URL")
    if env_url:
        return env_url

    # When running in a build environment like Railway's, where the database
    # is not available at build time, we can use a dummy URL. This allows
    # Alembic to generate the migration scripts without a live connection.
    # The actual migrations will run against the real database at runtime.
    # We detect a build environment by checking for common CI/build variables.
    if os.getenv("CI") or os.getenv("RAILWAY_STATIC_URL"):
        print("WARNING: Using dummy DATABASE_URL for build process.")
        return "postgresql+psycopg://dummy:dummy@localhost/dummy"

    ini_url = config.get_main_option("sqlalchemy.url")
    if ini_url:
        return ini_url
    raise RuntimeError("DATABASE_URL must be set for Alembic migrations")


def run_migrations_offline() -> None:
    url = _database_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    section = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = _database_url()

    connectable = engine_from_config(
        section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        future=True,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
