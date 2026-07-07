"""Helpers for checking Alembic migration state."""

from __future__ import annotations

from pathlib import Path

from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import text
from sqlalchemy.engine import Engine


def alembic_config(database_url: str | None = None) -> Config:
    """Build Alembic config for this project."""
    root = Path(__file__).resolve().parents[2]
    config = Config(str(root / "alembic.ini"))
    if database_url:
        config.set_main_option("sqlalchemy.url", database_url)
    return config


def migration_head(database_url: str | None = None) -> str:
    """Return the current Alembic script head revision."""
    script = ScriptDirectory.from_config(alembic_config(database_url))
    return script.get_current_head()


def database_revision(engine: Engine) -> str | None:
    """Return the database Alembic revision, or None when absent."""
    with engine.connect() as conn:
        try:
            context = MigrationContext.configure(conn)
            return context.get_current_revision()
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
