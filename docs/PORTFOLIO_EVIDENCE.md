# Portfolio Evidence

**Run date:** July 7, 2026  
**Target:** CTO review of a portfolio-grade regulated AI/RAG retrieval prototype

This repository demonstrates a real local workflow for encrypted retrieval:
FastAPI, PostgreSQL, Alembic migrations, tenant-scoped keys, encrypted document
storage, keyword-token retrieval, readiness checks, and sanitized audit rows.
It is not externally audited and is not production-certified cryptography.

## Verification Summary

| Check | Result |
| --- | --- |
| Full pytest suite, Python 3.11 | `774 passed, 1 skipped, 11 warnings in 69.89s` |
| Full pytest suite, Python 3.12 | `774 passed, 1 skipped, 17 warnings in 73.58s` |
| Focused API/security/storage suite | `104 passed in 2.19s` |
| Alembic migration smoke | `upgrade -> 20260706_0001` succeeded |
| Docker Compose build/start | Passed |
| `/ready` in Compose | `200 OK`, migration `20260706_0001` at head |
| Document ingest in Compose | Passed with AES-GCM and persisted tenant key ID |
| RAG retrieval in Compose | Passed with plaintext candidate for authorized caller |
| API restart persistence | Passed; same document returned after `docker compose restart api` |
| Audit rows | `document.encrypt`, `document.search`, `document.decrypt`, and `rag.retrieve` present |

## Commands Used

```bash
PYTHONPATH=src python3.11 -m pytest -q \
  -W ignore::DeprecationWarning \
  -W ignore::RuntimeWarning

env DATABASE_URL=sqlite+pysqlite:////private/tmp/encrypted_ir_portfolio_alembic_2.db \
  alembic upgrade head

docker compose up --build -d
curl -s -i http://localhost:8000/ready
curl -s -X POST http://localhost:8000/v1/documents \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: local-demo-key' \
  -d '{"doc_id":"portfolio-evidence-doc-20260707","content":"Portfolio evidence document covering fraud risk controls and regulated RAG retrieval persistence.","metadata":{"source":"portfolio-evidence","date":"2026-07-07"}}'
curl -s -X POST http://localhost:8000/v1/rag/retrieve \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: local-demo-key' \
  -d '{"query":"fraud risk controls","top_k":5,"include_plaintext":true}'
docker compose restart api
curl -s -X POST http://localhost:8000/v1/rag/retrieve \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: local-demo-key' \
  -d '{"query":"fraud risk controls","top_k":5,"include_plaintext":true}'
docker compose down
```

## Benchmark Results

Generated with `python -m encrypted_ir.tools.benchmark_retrieval` using
SQLite in-memory storage for deterministic local measurements.

| Documents | Ingest all docs | Search | Decrypt one doc | RAG retrieve top 10 with plaintext |
| ---: | ---: | ---: | ---: | ---: |
| 100 | 123.25 ms | 1.20 ms | 1.07 ms | 10.58 ms |
| 1,000 | 1132.36 ms | 2.39 ms | 0.96 ms | 11.99 ms |
| 10,000 | 11339.41 ms | 17.85 ms | 0.94 ms | 33.57 ms |

Reports:
- `benchmarks/reports/retrieval_100.md`
- `benchmarks/reports/retrieval_1000.md`
- `benchmarks/reports/retrieval_10000.md`

## What Is Real

- Durable encrypted-document workflow backed by PostgreSQL in Docker Compose.
- Alembic-managed schema for tenant keys, encrypted documents, search tokens,
  and audit rows.
- Tenant-scoped document encryption keys and search-token keys persisted through
  the database storage backend.
- OIDC/JWKS verification path and strict production settings validation.
- AWS KMS wrapped-master-key path implemented and unit-tested with fakes/mocks.
- `/ready` gates database, migration, auth, and key-provider posture.
- Endpoint audit records are sanitized and avoid plaintext, raw queries, tokens,
  and key material.

## Known Production Gaps

- No live AWS KMS or real IdP credentials were used in this evidence run.
- Audit rows are database records, not immutable external logs or SIEM events.
- Retrieval is deterministic keyword-token search, not vector search, PIR, ORAM,
  or zero-leakage retrieval.
- Custom ORE/SSE code remains prototype/research-oriented and unaudited.
- No Terraform/CDK, IAM policy review, TLS termination, WAF, SLOs, log retention,
  backup/restore drill, or external penetration test is included.

## CTO Review Framing

Use this as a portfolio-grade prototype showing how privacy-preserving retrieval
infrastructure for regulated RAG can be designed and verified locally. Do not
present it as production-certified cryptography or a completed compliance system.
