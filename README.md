# Privacy-Preserving Retrieval Prototype for Regulated AI/RAG

A Python prototype for encrypted retrieval infrastructure in regulated AI and financial-services settings. It demonstrates how encrypted document storage, tenant-scoped keyword retrieval, key lifecycle controls, audit records, and API hardening can support a RAG-style retrieval boundary without presenting the project as production-certified cryptography.

This repo is strongest as a CTO portfolio artifact: real enough to run locally with PostgreSQL and FastAPI, honest enough to document leakage and production gaps.

## What Is Real

- FastAPI service with health/readiness checks and versioned API routes.
- Docker Compose stack with PostgreSQL persistence.
- Alembic migration for documents, keyword tokens, key metadata, and audit entries.
- AES-GCM encrypted document storage for the durable API workflow.
- Tenant-scoped deterministic keyword tokens for retrieval.
- Key lifecycle primitives, file/database storage backends, and AWS KMS abstraction.
- OIDC/JWKS production configuration path plus local demo auth for Compose.
- Audit records that avoid plaintext, raw queries, tokens, and key material.
- Benchmarks and evidence docs for local portfolio review.

## Prototype Boundaries

- This is not externally audited and is not production-certified cryptography.
- Custom ORE and SSE helpers are prototype/research-oriented and need independent review before sensitive production use.
- The local demo auth path is for development only; production requires real identity, policy, and secret management.
- RAG support is retrieval-only. There are no embeddings, vector database, model calls, or prompt orchestration in this repo.
- Docker Compose is a local evidence path, not a cloud deployment.

## Run The Portfolio Demo

```bash
docker compose up --build
```

Open the API docs at:

```text
http://localhost:8000/docs
```

Ingest an encrypted document:

```bash
curl -X POST http://localhost:8000/v1/documents \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: local-demo-key' \
  -d '{"doc_id":"risk-001","content":"Quarterly fraud risk report for regulated RAG retrieval","metadata":{"source":"demo"}}'
```

Retrieve RAG-ready candidates:

```bash
curl -X POST http://localhost:8000/v1/rag/retrieve \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: local-demo-key' \
  -d '{"query":"fraud risk","top_k":3,"include_plaintext":true}'
```

The Compose stack enables `local-demo-key` through explicit dev-only auth. Disable `ENCRYPTED_IR_DEV_AUTH_ENABLED` and configure OIDC/JWKS before treating the API as anything beyond a local demo.

See [docs/CTO_DEMO_SCRIPT.md](docs/CTO_DEMO_SCRIPT.md) and [docs/DOCKER_COMPOSE_SMOKE_TEST.md](docs/DOCKER_COMPOSE_SMOKE_TEST.md) for the review flow.

## Install Locally

```bash
git clone https://github.com/MysterionRise/encrypted-information-retrieval.git
cd encrypted-information-retrieval

python3.11 -m pip install -r requirements.txt
python3.11 -m pip install -e .
```

Optional research dependencies for homomorphic encryption and post-quantum demos:

```bash
python3.11 -m pip install -r requirements-research.txt
```

## Useful Commands

```bash
PYTHONPATH=src python3.11 -m pytest -q -W ignore::DeprecationWarning
python3.11 -m black --check src tests
python3.11 -m ruff check src tests
PYTHONPATH=src python3.11 -m mypy src/encrypted_ir --ignore-missing-imports --no-strict-optional
python3.11 -m bandit -r src -ll -f screen
python3.11 -m build
python3.11 -m twine check dist/*
```

Generate a KMS-wrapped master key when AWS credentials and a KMS key are available:

```bash
python -m encrypted_ir.tools.generate_kms_master_key \
  --kms-key-id alias/encrypted-ir \
  --region us-east-1
```

Run the retrieval benchmark locally:

```bash
python -m encrypted_ir.tools.benchmark_retrieval \
  --database-url sqlite+pysqlite:///:memory: \
  --documents 1000 \
  --report benchmarks/reports/latest_retrieval.md
```

## Documentation

Read these first:

- [docs/PORTFOLIO_EVIDENCE.md](docs/PORTFOLIO_EVIDENCE.md): latest portfolio evidence and verification summary.
- [docs/CTO_DEMO_SCRIPT.md](docs/CTO_DEMO_SCRIPT.md): five-minute review script.
- [docs/LEAKAGE_AND_ENDPOINTS.md](docs/LEAKAGE_AND_ENDPOINTS.md): API leakage map and production boundary.
- [docs/DOCKER_COMPOSE_SMOKE_TEST.md](docs/DOCKER_COMPOSE_SMOKE_TEST.md): persistence smoke test.
- [docs/README.md](docs/README.md): documentation map and accuracy guidance.

Reference docs such as architecture, threat model, compliance notes, and backlog are useful context, but some include target-state or historical planning language. Treat portfolio evidence, executable tests, and the current code as the source of truth.

## Security Notes

Encrypted retrieval always leaks something:

- deterministic tokens and blind indexes leak equality within their configured scope,
- keyword retrieval leaks query repetition, result sizes, and access patterns,
- ORE reveals order through explicit comparisons,
- optional plaintext retrieval for RAG must be policy-gated and audited,
- local demo secrets are not a substitute for production KMS/HSM policy.

Use the project to discuss architecture and controls, not to claim compliance or audited cryptographic assurance.

## Roadmap

The next steps that would most improve production credibility are:

1. Validate the production OIDC/JWKS and AWS KMS paths against real cloud tenants.
2. Add immutable audit export to a SIEM or append-only log sink.
3. Add deployment IaC, TLS termination, backup/restore drills, and SLO dashboards.
4. Replace prototype retrieval primitives where stronger leakage guarantees are required.
5. Commission external cryptographic and application-security review.

## License

MIT License. See [LICENSE](LICENSE).
