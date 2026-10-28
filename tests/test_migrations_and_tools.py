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


def test_retrieval_benchmark_writes_json_and_markdown_with_provenance(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_SHA", raising=False)
    status = benchmark_retrieval.main(
        [
            "--documents",
            "5",
            "8",
            "--rounds",
            "3",
            "--warmup",
            "1",
            "--output-dir",
            str(tmp_path),
            "--commit",
            "abc1234",
            "--dirty",
        ]
    )

    assert status == 0
    result = json.loads((tmp_path / "retrieval_8.json").read_text())
    assert (tmp_path / "retrieval_5.json").exists()
    prov = result["provenance"]
    assert (prov["commit"], prov["dirty_tree"]) == ("abc1234", True)
    assert set(prov) >= {"generated_at", "cpu_model", "cpu_count", "os", "python", "sqlalchemy"}
    assert prov["database"]["dialect"] == "sqlite"
    assert prov["database"]["driver"] == "pysqlite"
    assert result["parameters"]["documents"] == 8
    assert result["corpus"]["rows_in_database_before"] == 0  # a fresh in-memory database
    ops = result["operations"]
    assert set(ops) == {"ingest", "search_or", "search_and", "get_document", "rag_retrieve"}
    assert ops["ingest"]["n"] == 8
    assert ops["rag_retrieve"]["n"] == 3
    # Three samples are too few for p95 and p99.
    assert ops["search_or"]["p95_ms"] is None and ops["search_or"]["p99_ms"] is None
    # Two of the eight documents are about fraud; all mention controls.
    assert result["corpus"]["documents_matching_and"] == 2
    assert ops["search_and"]["results"] == 2

    markdown = (tmp_path / "retrieval_8.md").read_text()
    assert markdown == benchmark_retrieval.render_markdown(result)
    assert "`abc1234` (uncommitted changes)" in markdown
    assert "| n/a |" in markdown


def test_retrieval_benchmark_takes_the_commit_from_github_sha(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_SHA", "f" * 40)
    benchmark_retrieval.main(
        ["--documents", "2", "--rounds", "1", "--warmup", "0", "--output-dir", str(tmp_path)]
    )

    result = json.loads((tmp_path / "retrieval_2.json").read_text())
    assert result["provenance"]["commit"] == "f" * 40


def test_benchmark_percentiles_need_enough_samples():
    twenty = benchmark_retrieval.summarize([float(i) for i in range(1, 21)])
    hundred = benchmark_retrieval.summarize([float(i) for i in range(1, 101)])

    assert twenty["n"] == 20 and twenty["p95_ms"] is not None and twenty["p99_ms"] is None
    assert hundred["p50_ms"] == 50.5
    assert hundred["p99_ms"] is not None and hundred["p95_ms"] <= hundred["p99_ms"] <= 100
    assert benchmark_retrieval.summarize([4.0])["p50_ms"] == 4.0


def test_benchmark_refuses_an_unmigrated_database(monkeypatch):
    class Dialect:
        name = "postgresql"

    class Engine:
        dialect = Dialect()

    monkeypatch.setattr(
        benchmark_retrieval,
        "migration_status",
        lambda engine, url: {"current": None, "head": "20261028_0005", "at_head": False},
    )
    with pytest.raises(SystemExit, match="upgrade head"):
        benchmark_retrieval._prepare(Engine(), "postgresql+psycopg://example/db")


@pytest.mark.parametrize("argv", [["--documents", "0"], ["--rounds", "0"], ["--search-limit", "0"]])
def test_benchmark_rejects_bad_arguments(tmp_path, argv):
    with pytest.raises(SystemExit):
        benchmark_retrieval.main([*argv, "--output-dir", str(tmp_path)])


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


def test_portfolio_evidence_benchmark_table_matches_the_reports():
    """docs/PORTFOLIO_EVIDENCE.md must be re-rendered whenever a benchmark report changes."""
    assert _load_script("render_evidence").main(["--check"]) == 0


def test_render_evidence_builds_a_row_per_report(tmp_path, monkeypatch):
    render = _load_script("render_evidence")
    monkeypatch.delenv("GITHUB_SHA", raising=False)
    out = tmp_path / "benchmarks" / "reports" / "sqlite-memory"
    benchmark_retrieval.main(
        ["--documents", "5", "--rounds", "3", "--warmup", "0", "--output-dir", str(out)]
        + ["--commit", "0123456789abcdef"]
    )

    section = render.render_benchmarks(
        render.load_benchmarks(tmp_path / "benchmarks" / "reports"), root=tmp_path
    )

    [row] = [line for line in section.splitlines() if line.startswith("| SQLite")]
    assert "(in memory) | 5 |" in row
    assert " / n/a |" in row  # three samples: no p95
    assert "(../benchmarks/reports/sqlite-memory/retrieval_5.md)" in row
    assert "commit `0123456789ab`" in section


def test_render_evidence_needs_the_markers():
    render = _load_script("render_evidence")
    with pytest.raises(SystemExit, match="generated:benchmarks"):
        render.apply("no markers here", {"benchmarks": "x"})
    assert (
        render.apply(
            "<!-- generated:benchmarks:begin -->\nold\n<!-- generated:benchmarks:end -->",
            {"benchmarks": "new\n"},
        )
        == "<!-- generated:benchmarks:begin -->\nnew\n<!-- generated:benchmarks:end -->"
    )
