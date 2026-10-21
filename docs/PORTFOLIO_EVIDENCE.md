# Portfolio Evidence

**Run date:** July 7 and 8, 2026, at commit `d52d63d`  
**Target:** CTO review of a portfolio-grade regulated AI/RAG retrieval prototype

> This is the only dated evidence run so far. It predates the Phase 0 work in
> [ROADMAP.md](ROADMAP.md). A fresh run on the release commit is part of [#51](https://github.com/MysterionRise/encrypted-information-retrieval/issues/51). Since this
> run, CI also runs the research-module tests and a Docker Compose smoke test.

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
- Custom ORE/SSE code remains prototype/research-oriented and unaudited. The ORE prototype's
  comparison needs no key, so ciphertext holders learn total order; see
  [THREAT_MODEL.md](THREAT_MODEL.md).
- No Terraform/CDK, IAM policy review, TLS termination, WAF, SLOs, log retention,
  backup/restore drill, or external penetration test is included.

## Status and Limitations

This section absorbs the former `CURRENT_STATUS.md`.

**What is verified**
- The FastAPI app, database migrations, encrypted document storage, tenant-scoped retrieval, key
  metadata and audit tables are implemented and tested.
- Dev auth rejects unsigned `alg:none` JWTs and requires signed HS256 tokens.
- `pyproject.toml` is the packaging source of truth; `setup.py` is a compatibility shim.

**Known limitations**
- No external cryptographic or application-security audit has been performed.
- Local demo auth, local master keys and in-memory demos are not production identity or
  key-management controls.
- Retrieval leaks equality, query repetition, result sizes and access patterns, depending on the
  primitive and endpoint. See [LEAKAGE_AND_ENDPOINTS.md](LEAKAGE_AND_ENDPOINTS.md).
- RAG support stops at retrieval and authorized context release. The repository does not call an
  LLM or run a vector database.
- Regulatory mapping material is discussion only. The old compliance notes are archived under
  [archive/](archive/README.md).

**Production-readiness gaps** are tracked as issues and ordered in [ROADMAP.md](ROADMAP.md).

### Reproduce locally

```bash
make test                 # full pytest suite (set POSTGRES_TEST_DATABASE_URL to include the Postgres test)
make lint                 # ruff, bandit, mypy
make security             # bandit and dependency audit
python -m build && twine check dist/*
PYTHONPATH=src python examples/portfolio_demo.py   # dependency-light library demo
```

The Docker Compose flow is in [CTO_DEMO_SCRIPT.md](CTO_DEMO_SCRIPT.md).

## CTO Review Framing

Use this as a portfolio-grade prototype showing how privacy-preserving retrieval
infrastructure for regulated RAG can be designed and verified locally. Do not
present it as production-certified cryptography or a completed compliance system.
