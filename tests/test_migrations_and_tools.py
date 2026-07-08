"""Tests for migrations and CLI helper modules."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from encrypted_ir.database import create_database_engine
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
