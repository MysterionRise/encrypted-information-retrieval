"""Tests for migrations and CLI helper modules."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import insert, inspect, select, text

from encrypted_ir import migrations
from encrypted_ir.database import audit_log_table, create_database_engine, metadata
from encrypted_ir.migrations import (
    alembic_config,
    database_revision,
    migration_head,
    migration_status,
)
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


def test_configured_url_wins_over_database_url(tmp_path, monkeypatch):
    """alembic_config(url) migrates that URL even when DATABASE_URL names another database."""
    other = tmp_path / "other.db"
    target = tmp_path / "target.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{other}")

    command.upgrade(alembic_config(f"sqlite+pysqlite:///{target}"), "head")

    assert target.exists()
    assert not other.exists()


def test_alembic_cli_config_uses_database_url(tmp_path, monkeypatch):
    """With no URL configured (as in alembic.ini), the environment names the database."""
    database = tmp_path / "from-env.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{database}")

    command.upgrade(alembic_config(), "head")

    engine = create_database_engine(f"sqlite+pysqlite:///{database}")
    try:
        assert migration_status(engine)["at_head"] is True
    finally:
        engine.dispose()


def test_no_database_url_is_an_error(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(RuntimeError, match="No database URL"):
        command.upgrade(alembic_config(), "head")


def test_url_with_percent_encoding(tmp_path):
    """URL-encoded characters (a password like p@ss, a query option) survive Alembic's config."""
    url = f"sqlite+pysqlite:///{tmp_path / 'p%40ss.db'}"
    config = alembic_config(url)
    assert config.get_main_option("sqlalchemy.url") == url

    command.upgrade(config, "head")

    assert (tmp_path / "p@ss.db").exists()  # SQLAlchemy decoded the URL Alembic passed on


def test_alembic_ini_names_no_database():
    ini = (Path(__file__).resolve().parents[1] / "alembic.ini").read_text()
    assert not any(line.strip().startswith("sqlalchemy.url") for line in ini.splitlines())


class TestMigrationsCli:
    def test_upgrade_current_and_downgrade(self, tmp_path, monkeypatch, capsys):
        url = f"sqlite+pysqlite:///{tmp_path / 'cli.db'}"
        monkeypatch.setenv("DATABASE_URL", url)

        assert migrations.main(["upgrade", "head"]) == 0
        assert migrations.main(["current"]) == 0
        assert migration_head(url) in capsys.readouterr().out

        assert migrations.main(["--database-url", url, "downgrade", "20261021_0003"]) == 0
        engine = create_database_engine(url)
        try:
            assert database_revision(engine) == "20261021_0003"
        finally:
            engine.dispose()

    def test_requires_a_database_url(self, monkeypatch, capsys):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        assert migrations.main(["upgrade"]) == 2
        assert "DATABASE_URL" in capsys.readouterr().err


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
def test_migrated_schema_matches_models(request, tmp_path, database_kind):
    """The Alembic head must produce exactly the tables the application code declares."""
    if database_kind == "postgres":
        database_url = request.getfixturevalue("require_postgres")
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
    makefile = (Path(__file__).resolve().parents[1] / "Makefile").read_text()

    assert "PYTHON ?= python3.11" in makefile
    assert "PYTHONPATH=src:$$PYTHONPATH $(PYTHON) -m pytest" in makefile
    assert "$(PYTHON) -m black" in makefile
    assert "$(PYTHON) -m ruff" in makefile
    assert "$(PYTHON) -m bandit" in makefile
    assert "PYTHONPATH=src:$$PYTHONPATH python -m pytest" not in makefile


def _load_script(name: str):
    path = Path(__file__).resolve().parents[1] / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _bench_report(path, medians: dict[str, float]) -> Path:
    report = {"benchmarks": [{"fullname": n, "stats": {"median": m}} for n, m in medians.items()]}
    path.write_text(json.dumps(report))
    return path


def test_compare_benchmarks(tmp_path, capsys):
    compare = _load_script("compare_benchmarks")
    baseline = tmp_path / "baseline.json"
    before = _bench_report(tmp_path / "before.json", {"a": 1.0, "b": 2.0, "gone": 1.0})
    assert compare.main([str(before), "--baseline", str(baseline), "--update"]) == 0

    within = _bench_report(tmp_path / "within.json", {"a": 2.9, "b": 1.0, "new": 5.0})
    assert compare.main([str(within), "--baseline", str(baseline)]) == 0
    out = capsys.readouterr().out
    assert "new" in out and "missing" in out

    slower = _bench_report(tmp_path / "slower.json", {"a": 3.5, "b": 2.0})
    assert compare.main([str(slower), "--baseline", str(baseline)]) == 1
    assert "REGRESSION" in capsys.readouterr().out
    assert compare.main([str(slower), "--baseline", str(baseline), "--threshold", "4"]) == 0
