"""Alembic environment.

The database URL always comes from CardioAuth settings (never from alembic.ini), and
the production startup guards run before any connection is opened, so a misconfigured
production deployment cannot migrate silently.
"""

from __future__ import annotations

import logging
import os
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cardioauth.db import Base  # noqa: E402
from cardioauth.settings import Settings, get_settings  # noqa: E402

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

logger = logging.getLogger("alembic.env")

target_metadata = Base.metadata


def _database_url() -> str:
    # -x db_url=... overrides settings; used by tests to migrate an ephemeral database.
    x_args = context.get_x_argument(as_dictionary=True)
    if url := x_args.get("db_url"):
        return url
    if url := os.environ.get("CARDIOAUTH_MIGRATION_DATABASE_URL"):
        return url
    settings: Settings = get_settings()
    settings.assert_runtime_safe()  # production guards run before touching a database
    return settings.database_url


def run_migrations_offline() -> None:
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        include_schemas=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    section = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = _database_url()
    connectable = engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            include_schemas=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
