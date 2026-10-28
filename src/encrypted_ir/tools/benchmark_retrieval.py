"""Benchmark the durable encrypted retrieval path, with provenance.

    python -m encrypted_ir.tools.benchmark_retrieval --documents 100 1000 \\
        --output-dir benchmarks/reports/sqlite-memory --commit "$(git rev-parse HEAD)"

For each corpus size, a fresh tenant (with a random master key) ingests that many documents,
and every ingest is timed. Then searches (OR and AND), single-document gets and RAG retrievals
with plaintext each run ``--warmup`` times untimed and ``--rounds`` times timed.

Each size writes ``retrieval_<N>.json`` and ``retrieval_<N>.md`` (rendered from the JSON) to
``--output-dir``. They record the commit, the time, the hardware, the OS, Python, the SQLAlchemy
driver and the database server, so a number can be traced to the run that produced it.
Percentiles need enough samples: p95 is reported from 20 samples and p99 from 100, and "n/a" below
that.

The tool never runs git: pass ``--commit`` (and ``--dirty`` for an uncommitted tree), or it
falls back to ``GITHUB_SHA``. A PostgreSQL database must already be migrated to head
(``python -m encrypted_ir.migrations upgrade head``). SQLite schemas are created by the tool.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sqlite3
import statistics
import sys
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import sqlalchemy
from sqlalchemy import func, select
from sqlalchemy.engine import Engine

from encrypted_ir import __version__
from encrypted_ir.database import (
    create_database_engine,
    create_database_schema,
    documents_table,
)
from encrypted_ir.document_service import DocumentService
from encrypted_ir.migrations import migration_status

SCHEMA_VERSION = 1
QUERY = "fraud controls"
RAG_TOP_K = 10
GET_DOC_POOL = 100
P95_MIN_SAMPLES = 20
P99_MIN_SAMPLES = 100
SQLITE_MEMORY_URL = "sqlite+pysqlite:///:memory:"
TOPICS = ("fraud", "aml", "credit", "risk", "compliance")


def doc_content(i: int) -> str:
    """Deterministic content: one document in five is about fraud, all mention controls."""
    return (
        f"Document {i} covers {TOPICS[i % len(TOPICS)]} controls for regulated RAG retrieval. "
        f"The benchmark uses deterministic content group {i % 10}."
    )


def summarize(samples_ms: list[float]) -> dict[str, Any]:
    """Count, mean, min, max and percentiles of ``samples_ms`` (milliseconds)."""
    n = len(samples_ms)
    if n == 0:
        raise ValueError("no samples")
    cuts = statistics.quantiles(samples_ms, n=100, method="inclusive") if n > 1 else None
    return {
        "n": n,
        "mean_ms": statistics.fmean(samples_ms),
        "min_ms": min(samples_ms),
        "p50_ms": statistics.median(samples_ms),
        "p95_ms": cuts[94] if cuts and n >= P95_MIN_SAMPLES else None,
        "p99_ms": cuts[98] if cuts and n >= P99_MIN_SAMPLES else None,
        "max_ms": max(samples_ms),
    }


def _timed(fn: Callable[[], Any], warmup: int, rounds: int) -> tuple[list[float], Any]:
    for _ in range(warmup):
        fn()
    samples: list[float] = []
    result: Any = None
    for _ in range(rounds):
        start = time.perf_counter_ns()
        result = fn()
        samples.append((time.perf_counter_ns() - start) / 1e6)
    return samples, result


def _cpu_model() -> str:
    try:
        with open("/proc/cpuinfo") as cpuinfo:
            for line in cpuinfo:
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or platform.machine() or "unknown"


def _server_version(engine: Engine) -> str:
    if engine.dialect.name == "sqlite":
        return sqlite3.sqlite_version
    with engine.connect() as conn:
        info = conn.dialect.server_version_info
    return ".".join(str(part) for part in info) if info else "unknown"


def provenance(engine: Engine, commit: str | None, dirty: bool) -> dict[str, Any]:
    """Where and how a result was produced."""
    return {
        "commit": commit or os.environ.get("GITHUB_SHA") or "unknown",
        "dirty_tree": dirty,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "package_version": __version__,
        "python": f"{platform.python_implementation()} {platform.python_version()}",
        "os": platform.platform(),
        "cpu_model": _cpu_model(),
        "cpu_count": os.cpu_count(),
        "sqlalchemy": sqlalchemy.__version__,
        "database": {
            "dialect": engine.dialect.name,
            "driver": engine.dialect.driver,
            "server_version": _server_version(engine),
            "url": engine.url.render_as_string(hide_password=True),
        },
    }


def _prepare(engine: Engine, database_url: str) -> None:
    if engine.dialect.name == "sqlite":
        create_database_schema(engine)
        return
    status = migration_status(engine, database_url)
    if not status["at_head"]:
        raise SystemExit(
            f"the database is at revision {status['current']}, not {status['head']}: run "
            "`python -m encrypted_ir.migrations upgrade head` first"
        )


def run_size(
    engine: Engine,
    documents: int,
    rounds: int,
    warmup: int,
    search_limit: int,
    run_info: dict[str, Any],
) -> dict[str, Any]:
    """Ingest ``documents`` for a fresh tenant and time every operation."""
    with engine.connect() as conn:
        rows_before = conn.execute(select(func.count()).select_from(documents_table)).scalar_one()
    service = DocumentService(engine, os.urandom(32))
    tenant = f"bench-{uuid.uuid4().hex[:12]}"

    warm_tenant = f"{tenant}-warmup"
    for i in range(warmup):
        service.ingest_document(warm_tenant, f"warm-{i:06d}", doc_content(i))

    ingest_samples: list[float] = []
    ingest_start = time.perf_counter_ns()
    for i in range(documents):
        start = time.perf_counter_ns()
        service.ingest_document(
            tenant, f"doc-{i:06d}", doc_content(i), metadata={"seq": i, "group": i % 10}
        )
        ingest_samples.append((time.perf_counter_ns() - start) / 1e6)
    ingest_seconds = (time.perf_counter_ns() - ingest_start) / 1e9

    matching = len(service.search_documents(tenant, QUERY, "AND", limit=documents))
    search_or, or_results = _timed(
        lambda: service.search_documents(tenant, QUERY, "OR", limit=search_limit), warmup, rounds
    )
    search_and, and_results = _timed(
        lambda: service.search_documents(tenant, QUERY, "AND", limit=search_limit), warmup, rounds
    )
    pool = [f"doc-{i:06d}" for i in range(min(documents, GET_DOC_POOL))]
    counter = iter(range(warmup + rounds))
    get_one, _ = _timed(
        lambda: service.get_document(tenant, pool[next(counter) % len(pool)]), warmup, rounds
    )
    rag, rag_results = _timed(
        lambda: service.retrieve_for_rag(tenant, QUERY, top_k=RAG_TOP_K, include_plaintext=True),
        warmup,
        rounds,
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "tool": "encrypted_ir.tools.benchmark_retrieval",
        "provenance": run_info,
        "parameters": {
            "documents": documents,
            "rounds": rounds,
            "warmup": warmup,
            "search_limit": search_limit,
            "query": QUERY,
            "rag_top_k": RAG_TOP_K,
        },
        "corpus": {
            "tenant_id": tenant,
            "documents_matching_and": matching,
            "rows_in_database_before": rows_before,
        },
        "ingest": {
            "total_seconds": ingest_seconds,
            "documents_per_second": documents / max(ingest_seconds, 1e-9),
        },
        "operations": {
            "ingest": {**summarize(ingest_samples), "unit": "one document"},
            "search_or": {**summarize(search_or), "results": len(or_results)},
            "search_and": {**summarize(search_and), "results": len(and_results)},
            "get_document": summarize(get_one),
            "rag_retrieve": {**summarize(rag), "results": len(rag_results)},
        },
    }


OPERATION_LABELS = {
    "ingest": "Ingest one document (encrypt, tokenize, audit, commit)",
    "search_or": "Search, OR",
    "search_and": "Search, AND",
    "get_document": "Get and decrypt one document",
    "rag_retrieve": "RAG retrieve top 10 with plaintext",
}


def _ms(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def render_markdown(result: dict[str, Any]) -> str:
    """The Markdown report for one result, generated from its JSON."""
    prov = result["provenance"]
    params = result["parameters"]
    corpus = result["corpus"]
    db = prov["database"]
    dirty = " (uncommitted changes)" if prov["dirty_tree"] else ""
    lines = [
        f"# Retrieval Benchmark: {params['documents']} documents, {db['dialect']}",
        "",
        "Generated by `python -m encrypted_ir.tools.benchmark_retrieval` from the JSON next to "
        "this file. Do not edit by hand.",
        "",
        "| Provenance | Value |",
        "| --- | --- |",
        f"| Commit | `{prov['commit']}`{dirty} |",
        f"| Generated (UTC) | {prov['generated_at']} |",
        f"| Package version | {prov['package_version']} |",
        f"| CPU | {prov['cpu_model']}, {prov['cpu_count']} logical cores |",
        f"| OS | {prov['os']} |",
        f"| Python | {prov['python']} |",
        f"| SQLAlchemy | {prov['sqlalchemy']}, dialect `{db['dialect']}`, "
        f"driver `{db['driver']}` |",
        f"| Database server | {db['dialect']} {db['server_version']} (`{db['url']}`) |",
        "",
        f"Corpus: {params['documents']} documents for one fresh tenant; "
        f"{corpus['documents_matching_and']} of them match `{params['query']}` with AND. "
        f"Rows from other tenants already in the database: {corpus['rows_in_database_before']}.",
        "",
        f"Each read operation ran {params['warmup']} times untimed, then {params['rounds']} "
        f"times timed. Searches return at most {params['search_limit']} results. Ingest is "
        f"timed per document: {result['ingest']['total_seconds']:.2f} s in total, "
        f"{result['ingest']['documents_per_second']:.1f} documents per second.",
        "",
        "| Operation | n | mean ms | p50 ms | p95 ms | p99 ms | max ms | results |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for key, label in OPERATION_LABELS.items():
        op = result["operations"][key]
        lines.append(
            f"| {label} | {op['n']} | {_ms(op['mean_ms'])} | {_ms(op['p50_ms'])} | "
            f"{_ms(op['p95_ms'])} | {_ms(op['p99_ms'])} | {_ms(op['max_ms'])} | "
            f"{op.get('results', '')} |"
        )
    lines += [
        "",
        f"p95 needs at least {P95_MIN_SAMPLES} samples and p99 at least {P99_MIN_SAMPLES}; "
        '"n/a" means fewer were taken.',
        "",
        "What these numbers do not show: one process and one connection at a time, no network "
        "between the API and the client, no HTTP layer, and the database on the same machine. "
        "See benchmarks/README.md.",
        "",
        "Leakage note: retrieval uses deterministic keyword tokens. The server can observe token "
        "equality, query repetition, access patterns and result sizes.",
        "",
    ]
    return "\n".join(lines)


def write_result(result: dict[str, Any], output_dir: Path) -> tuple[Path, Path]:
    """Write ``retrieval_<N>.json`` and its rendered ``.md``."""
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = f"retrieval_{result['parameters']['documents']}"
    json_path = output_dir / f"{stem}.json"
    md_path = output_dir / f"{stem}.md"
    json_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    md_path.write_text(render_markdown(result))
    return json_path, md_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--database-url", default=SQLITE_MEMORY_URL)
    parser.add_argument("--documents", type=int, nargs="+", default=[1000])
    parser.add_argument("--rounds", type=int, default=200)
    parser.add_argument("--warmup", type=int, default=20)
    parser.add_argument("--search-limit", type=int, default=100)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--commit", help="Commit SHA of the code under test")
    parser.add_argument(
        "--dirty", action="store_true", help="The working tree had uncommitted changes"
    )
    args = parser.parse_args(argv)
    if min(args.documents) < 1 or args.rounds < 1 or args.warmup < 0 or args.search_limit < 1:
        parser.error("--documents, --rounds and --search-limit must be positive")

    for documents in args.documents:
        # A fresh in-memory database per size; any other database is shared, so the report
        # records how many rows were already there.
        engine = create_database_engine(args.database_url)
        try:
            _prepare(engine, args.database_url)
            run_info = provenance(engine, args.commit, args.dirty)
            result = run_size(
                engine, documents, args.rounds, args.warmup, args.search_limit, run_info
            )
        finally:
            engine.dispose()
        json_path, _ = write_result(result, args.output_dir)
        rag = result["operations"]["rag_retrieve"]
        print(
            f"{documents} documents: ingest {result['ingest']['documents_per_second']:.1f}/s, "
            f"RAG p50 {_ms(rag['p50_ms'])} ms -> {json_path}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
