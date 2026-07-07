"""Benchmark durable encrypted retrieval operations."""

from __future__ import annotations

import argparse
import statistics
import time
from pathlib import Path

from encrypted_ir.database import create_database_engine, create_database_schema
from encrypted_ir.document_service import DocumentService


def _doc_content(i: int) -> str:
    topic = ["fraud", "aml", "credit", "risk", "compliance"][i % 5]
    return (
        f"Document {i} covers {topic} controls for regulated RAG retrieval. "
        f"The portfolio benchmark uses deterministic content group {i % 10}."
    )


def _measure(fn, rounds: int = 1) -> tuple[float, object]:
    durations = []
    result = None
    for _ in range(rounds):
        start = time.perf_counter()
        result = fn()
        durations.append((time.perf_counter() - start) * 1000)
    return statistics.mean(durations), result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database-url", default="sqlite+pysqlite:///:memory:")
    parser.add_argument("--documents", type=int, default=1000)
    parser.add_argument("--tenant-id", default="benchmark-tenant")
    parser.add_argument("--auto-create", action="store_true")
    parser.add_argument("--report", default="")
    args = parser.parse_args()

    engine = create_database_engine(args.database_url)
    if args.auto_create or args.database_url.startswith("sqlite"):
        create_database_schema(engine)

    service = DocumentService(engine, b"0" * 32)

    ingest_start = time.perf_counter()
    for i in range(args.documents):
        service.ingest_document(
            tenant_id=args.tenant_id,
            doc_id=f"doc-{i:06d}",
            content=_doc_content(i),
            metadata={"seq": i, "group": i % 10},
        )
    ingest_ms = (time.perf_counter() - ingest_start) * 1000

    search_ms, matches = _measure(
        lambda: service.search_documents(args.tenant_id, "fraud controls", "AND", limit=25),
        rounds=10,
    )
    decrypt_ms, _ = _measure(
        lambda: service.get_document(args.tenant_id, matches[0].doc_id),
        rounds=10,
    )
    rag_ms, candidates = _measure(
        lambda: service.retrieve_for_rag(
            args.tenant_id,
            "fraud controls",
            top_k=10,
            include_plaintext=True,
        ),
        rounds=10,
    )

    report = f"""# Retrieval Benchmark Report

Documents: {args.documents}
Tenant: {args.tenant_id}

| Operation | Mean latency |
| --- | ---: |
| Ingest all documents | {ingest_ms:.2f} ms |
| Search fraud controls | {search_ms:.2f} ms |
| Decrypt one document | {decrypt_ms:.2f} ms |
| RAG retrieve top 10 with plaintext | {rag_ms:.2f} ms |

Matches returned: {len(matches)}
RAG candidates returned: {len(candidates)}

Leakage note: this benchmark uses deterministic keyword tokens. The server can
observe token equality, query repetition, access patterns, and result sizes.
"""

    if args.report:
        path = Path(args.report)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(report)
    else:
        print(report)


if __name__ == "__main__":
    main()
