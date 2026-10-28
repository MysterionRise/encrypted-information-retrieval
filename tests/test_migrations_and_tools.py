"""Tests for migrations and CLI helper modules."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import insert, inspect, select, text

from encrypted_ir.database import audit_log_table, create_database_engine, metadata
from encrypted_ir.migrations import alembic_config, migration_head, migration_status
from encrypted_ir.tools import benchmark_retrieval


def test_alembic_upgrade_reaches_head(tmp_path):
    db_path = tmp_path / "migration.db"
    database_url = f"sqlite+pysqlite:///{db_path}"

    command.upgrade(alembic_config(database_url), "head")
    engine = create_database_engine(database_url)
    status = migration_status(engine, database_url)

    assert status["current"] == migration_head(database_url)
    assert status["at_head"] is True


def _document_columns(database_url):
    engine = create_database_engine(database_url)
    try:
        return {column["name"] for column in inspect(engine).get_columns("encrypted_ir_documents")}
    finally:
        engine.dispose()


def test_migration_0002_round_trip_on_sqlite(tmp_path):
    database_url = f"sqlite+pysqlite:///{tmp_path / 'roundtrip.db'}"
    config = alembic_config(database_url)

    command.upgrade(config, "head")
    assert "deleted" not in _document_columns(database_url)

    command.downgrade(config, "20260706_0001")
    assert "deleted" in _document_columns(database_url)

    command.upgrade(config, "head")
    assert "deleted" not in _document_columns(database_url)


def test_migration_0004_keeps_legacy_audit_rows(tmp_path):
    database_url = f"sqlite+pysqlite:///{tmp_path / 'audit.db'}"
    config = alembic_config(database_url)
    command.upgrade(config, "20261021_0003")
    engine = create_database_engine(database_url)
    legacy = {"timestamp": "2026-10-01T00:00:00", "operation": "create", "key_id": "k1"}
    with engine.begin() as conn:
        conn.execute(insert(audit_log_table).values(tenant_id="t", key_id="k1", entry_json=legacy))

    try:
        command.upgrade(config, "head")
        with engine.connect() as conn:
            row = conn.execute(select(audit_log_table)).one()
        assert (row.entry_json, row.seq, row.entry_hash) == (legacy, None, None)
        assert "encrypted_ir_audit_chain_heads" in inspect(engine).get_table_names()

        command.downgrade(config, "20261021_0003")
        assert "encrypted_ir_audit_chain_heads" not in inspect(engine).get_table_names()
        columns = {c["name"] for c in inspect(engine).get_columns("encrypted_ir_audit_log")}
        assert "seq" not in columns
        with engine.connect() as conn:
            assert conn.execute(text("SELECT entry_json FROM encrypted_ir_audit_log")).all()
    finally:
        engine.dispose()


def test_migration_0005_round_trip(tmp_path):
    database_url = f"sqlite+pysqlite:///{tmp_path / 'rotation.db'}"
    config = alembic_config(database_url)
    command.upgrade(config, "head")
    engine = create_database_engine(database_url)
    try:
        assert "encrypted_keywords" in _document_columns(database_url)
        assert "encrypted_ir_key_rotations" in inspect(engine).get_table_names()

        command.downgrade(config, "20261027_0004")
        assert "encrypted_keywords" not in _document_columns(database_url)
        assert "encrypted_ir_key_rotations" not in inspect(engine).get_table_names()

        command.upgrade(config, "head")
        assert "encrypted_keywords" in _document_columns(database_url)
    finally:
        engine.dispose()


@pytest.mark.parametrize("database_kind", ["sqlite", "postgres"])
def test_migrated_schema_matches_models(tmp_path, database_kind):
    """The Alembic head must produce exactly the tables the application code declares."""
    if database_kind == "postgres":
        database_url = os.environ.get("POSTGRES_TEST_DATABASE_URL")
        if not database_url:
            pytest.skip("POSTGRES_TEST_DATABASE_URL is not set")
    else:
        database_url = f"sqlite+pysqlite:///{tmp_path / 'drift.db'}"

    command.upgrade(alembic_config(database_url), "head")
    engine = create_database_engine(database_url)
    try:
        with engine.connect() as conn:
            diff = compare_metadata(MigrationContext.configure(conn), metadata)
    finally:
        engine.dispose()

    assert diff == []


def test_retrieval_benchmark_writes_report(tmp_path, monkeypatch):
    report_path = tmp_path / "report.md"
    monkeypatch.setattr(
        "sys.argv",
        [
            "benchmark_retrieval",
            "--database-url",
            "sqlite+pysqlite:///:memory:",
            "--documents",
            "5",
            "--report",
            str(report_path),
        ],
    )

    benchmark_retrieval.main()

    text = Path(report_path).read_text()
    assert "Retrieval Benchmark Report" in text
    assert "Documents: 5" in text


def test_makefile_uses_configured_python_variable():
    makefile = Path("Makefile").read_text()

    assert "PYTHON ?= python3.11" in makefile
    assert "PYTHONPATH=src:$$PYTHONPATH $(PYTHON) -m pytest" in makefile
    assert "$(PYTHON) -m black" in makefile
    assert "$(PYTHON) -m ruff" in makefile
    assert "$(PYTHON) -m bandit" in makefile
    assert "PYTHONPATH=src:$$PYTHONPATH python -m pytest" not in makefile
