"""Alembic migration helpers and a small CLI.

Run migrations without ``alembic.ini`` (for example from the Docker image)::

    python -m encrypted_ir.migrations upgrade head
    python -m encrypted_ir.migrations current

The database is ``--database-url`` or the ``DATABASE_URL`` environment variable.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from typing import cast

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import text
from sqlalchemy.engine import Engine

# Migration scripts are package data, so this works from a source checkout and
# from an installed wheel. The repository's alembic.ini points at the same place.
SCRIPT_LOCATION = "encrypted_ir:alembic_migrations"


def alembic_config(database_url: str | None = None) -> Config:
    """Build Alembic config for this project."""
    config = Config(stdout=sys.stdout)  # the current stdout, not the one at import time
    config.set_main_option("script_location", SCRIPT_LOCATION)
    if database_url:
        config.set_main_option("sqlalchemy.url", database_url)
    return config


def migration_head(database_url: str | None = None) -> str:
    """Return the current Alembic script head revision."""
    script = ScriptDirectory.from_config(alembic_config(database_url))
    return cast(str, script.get_current_head())


def database_revision(engine: Engine) -> str | None:
    """Return the database Alembic revision, or None when absent."""
    with engine.connect() as conn:
        try:
            context = MigrationContext.configure(conn)
            return cast(str | None, context.get_current_revision())
        except Exception:
            return None


def database_connects(engine: Engine) -> bool:
    """Return whether the database accepts a trivial query."""
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    return True


def migration_status(
    engine: Engine, database_url: str | None = None
) -> dict[str, str | bool | None]:
    """Return database migration readiness information."""
    head = migration_head(database_url)
    current = database_revision(engine)
    return {
        "current": current,
        "head": head,
        "at_head": current == head,
    }


def main(argv: list[str] | None = None) -> int:
    """``upgrade``, ``downgrade`` or ``current`` against ``--database-url`` or DATABASE_URL."""
    parser = argparse.ArgumentParser(
        prog="python -m encrypted_ir.migrations", description="Run Encrypted IR migrations."
    )
    parser.add_argument("--database-url", help="Database URL (default: $DATABASE_URL)")
    commands = parser.add_subparsers(dest="command", required=True)
    upgrade = commands.add_parser("upgrade", help="Upgrade to a revision (default: head)")
    upgrade.add_argument("revision", nargs="?", default="head")
    downgrade = commands.add_parser("downgrade", help="Downgrade to a revision")
    downgrade.add_argument("revision")
    commands.add_parser("current", help="Print the database revision")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)-5.5s [%(name)s] %(message)s")

    database_url = args.database_url or os.environ.get("DATABASE_URL")
    if not database_url:
        print("error: set --database-url or DATABASE_URL", file=sys.stderr)
        return 2
    config = alembic_config(database_url)
    if args.command == "upgrade":
        command.upgrade(config, args.revision)
    elif args.command == "downgrade":
        command.downgrade(config, args.revision)
    else:
        command.current(config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
