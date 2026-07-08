# Current Status

**Verified date:** July 8, 2026  
**Positioning:** portfolio-grade encrypted retrieval prototype for regulated AI/RAG systems

This project is a real local prototype, not a production-certified cryptographic system. It is strongest for CTO review when framed around architecture, leakage trade-offs, implementation discipline, and clear next steps.

## Verified Locally

- FastAPI app, database migrations, encrypted document storage, tenant-scoped retrieval, key metadata, and audit tables are implemented.
- Local Docker Compose evidence exists for PostgreSQL persistence, restart survival, `/ready`, document ingest, RAG retrieval, and audit rows.
- In-process library primitives cover blind indexes, searchable encryption, ORE range comparisons, key lifecycle management, storage backends, and optional research modules.
- Dev auth now rejects unsigned `alg:none` JWTs and requires signed HS256 tokens for local JWT tests.
- `pyproject.toml` is the packaging source of truth; `setup.py` is a compatibility shim.
- CI now treats ruff, bandit, and mypy as required quality gates.

## Local Quality Commands

```bash
PYTHONPATH=src python3.11 -m pytest -q -W ignore::DeprecationWarning -W ignore::RuntimeWarning
PYTHONPATH=src python3.12 -m pytest -q -W ignore::DeprecationWarning -W ignore::RuntimeWarning
python3.11 -m black --check src tests examples
python3.11 -m ruff check src tests examples
python3.11 -m isort --check-only --profile black src tests examples
PYTHONPATH=src python3.11 -m mypy --disable-error-code redundant-cast src/encrypted_ir --ignore-missing-imports --no-strict-optional
python3.11 -m bandit -r src -ll -f screen
python3.11 -m build
python3.11 -m twine check dist/*
```

## Demo Paths

- FastAPI/PostgreSQL path: `docker compose up --build`, then use `/docs` or the curl flow in `docs/CTO_DEMO_SCRIPT.md`.
- Dependency-light local path: `PYTHONPATH=src python3.11 examples/portfolio_demo.py`.
- Benchmark path: `python -m encrypted_ir.tools.benchmark_retrieval --database-url sqlite+pysqlite:///:memory: --documents 1000 --report benchmarks/reports/latest_retrieval.md`.

## Known Limitations

- No external cryptographic audit has been performed.
- Local demo auth, local master keys, and in-memory demos are not production identity or key-management controls.
- Retrieval leaks equality, query repetition, result sizes, and access patterns depending on the primitive and endpoint used.
- ORE reveals order through explicit comparisons and should be treated as research/prototype code until reviewed.
- RAG support stops at retrieval and authorized context release; this repo does not call an LLM or operate a vector database.
- Compliance docs are control-mapping discussion material, not audit reports or legal opinions.

## Production-Readiness Gaps

1. Validate OIDC/JWKS and AWS KMS with real tenant infrastructure.
2. Add immutable audit export to SIEM or append-only storage.
3. Add IaC, TLS termination, backup/restore drills, SLO dashboards, and operational runbooks.
4. Replace or formally review prototype cryptographic primitives before sensitive production use.
5. Add policy enforcement for plaintext release into downstream RAG pipelines.
6. Commission external application-security and cryptographic review.
