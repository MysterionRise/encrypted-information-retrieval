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

## Core Versus Research Code

The `encrypted_ir` package exports only the durable document path and the standard constructions
it is built from: AES-GCM documents with HMAC keyword tokens, AES-SIV, HMAC blind indexes, key
management and the storage backends. Everything experimental lives in `encrypted_ir.research`:
the CLWW-style ORE, FF1, CKKS, post-quantum KEM and signatures, differential privacy,
forward-private SSE and the use-case demos. Importing that package issues a
`ResearchPrototypeWarning`, nothing in the core package or the API imports it, and its tests run in
`tests/research/`. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for what each prototype leaks.

## Prototype Boundaries

- This is not externally audited and is not production-certified cryptography.
- The research prototypes in `encrypted_ir.research` (ORE, forward-private SSE and others) are unaudited and need independent review before any sensitive use.
- The local demo auth path is for development only; production requires real identity, policy, and secret management.
- RAG support is retrieval-only. There are no embeddings, vector database, model calls, or prompt orchestration in this repo.
- Docker Compose is a local evidence path, not a cloud deployment.

## Run The Portfolio Demo

For a fast, dependency-light demo that exercises library APIs only:

```bash
PYTHONPATH=src python3.11 examples/portfolio_demo.py
```

The script prints deterministic JSON covering tenant-scoped blind indexes,
encrypted document search, ORE range query, key/audit lifecycle, and the RAG
retrieval privacy boundary.

For the API and PostgreSQL workflow:

```bash
docker compose up --build
```

Open the API docs at the URL below. Compose sets `ENCRYPTED_IR_ENABLE_DOCS=true`; without it,
`/docs`, `/redoc` and `/openapi.json` return 404.

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

The Compose stack enables `local-demo-key` through explicit dev-only auth. Dev auth is off by default, is refused unless `ENCRYPTED_IR_ENV=dev`, and needs `ENCRYPTED_IR_JWT_SECRET` of at least 32 bytes. Configure OIDC/JWKS before treating the API as anything beyond a local demo.

To run the API without Docker, against a local SQLite file:

```bash
export ENCRYPTED_IR_ENV=dev
export ENCRYPTED_IR_DEV_AUTH_ENABLED=true
export ENCRYPTED_IR_JWT_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
export ENCRYPTED_IR_DEV_API_KEY=local-demo-key
export ENCRYPTED_IR_ENABLE_DOCS=true
export DATABASE_URL=sqlite+pysqlite:///./encrypted_ir_dev.db
uvicorn encrypted_ir.api.main:create_app --factory
```

Without `ENCRYPTED_IR_MASTER_KEY_B64` the app generates a random master key at startup, so documents
from one run cannot be read in the next.

Auth and HTTP settings (all optional except where noted):

| Variable | Default | Meaning |
| --- | --- | --- |
| `ENCRYPTED_IR_DEV_AUTH_ENABLED` | `false` | Dev API key and HS256 dev tokens. Only allowed with `ENCRYPTED_IR_ENV=dev`. |
| `ENCRYPTED_IR_JWT_SECRET` | none | HS256 secret for dev tokens; required, at least 32 bytes, when dev auth is on. |
| `ENCRYPTED_IR_DEV_API_KEY` | none | Value accepted in `X-API-Key`. The API-key path is off when unset. |
| `ENCRYPTED_IR_DEV_TENANT_ID` | `local-demo` | Tenant for the dev API key. |
| `ENCRYPTED_IR_OIDC_ISSUER`, `_AUDIENCE`, `_JWKS_URL` | none | OIDC verification; all three are required in `prod`. |
| `ENCRYPTED_IR_OIDC_ALGORITHMS` | `RS256` | Comma-separated subset of `RS256`, `PS256`, `ES256`. |
| `ENCRYPTED_IR_JWT_LEEWAY_SECONDS` | `30` | Clock skew allowed for `exp` and `iat` (0 to 300). |
| `ENCRYPTED_IR_JWKS_TIMEOUT_SECONDS` | `5` | Timeout for fetching the JWKS. |
| `ENCRYPTED_IR_ENABLE_DOCS` | `false` | Serve `/docs`, `/redoc` and `/openapi.json`. |
| `ENCRYPTED_IR_MAX_BODY_BYTES` | `10485760` | Largest accepted request body. |
| `ENCRYPTED_IR_CORS_ORIGINS` | localhost origins | Comma-separated origins. `*` is refused in `prod` and never sent with credentials. |
| `ENCRYPTED_IR_LOG_LEVEL` | `INFO` | Level for the JSON logs on stdout. |
| `ENCRYPTED_IR_METRICS_TOKEN` | none | When set (at least 16 bytes), `GET /metrics` requires `Authorization: Bearer <token>`. |
| `ENCRYPTED_IR_RATE_LIMITS` | see below | JSON overrides, e.g. `{"document_search": [120, 60], "client": [600, 60]}` (max requests, window seconds). |
| `ENCRYPTED_IR_RATE_LIMIT_MAX_KEYS` | `10000` | Most rate-limit buckets kept per operation. |
| `ENCRYPTED_IR_TRUSTED_PROXIES` | none | Comma-separated proxy IPs or networks whose `X-Forwarded-For` is trusted for the client address. |

Every token must carry `exp`, `iat`, a tenant claim matching `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`
and a non-empty roles claim; OIDC tokens also need `aud` and `iss`.

The API logs JSON lines to stdout: one access line per request (method, route template, status,
latency, tenant) and any warnings, each carrying the request's `X-Request-ID` as
`correlation_id`. Values that look like keys, card numbers or email addresses are redacted.
Rate limits are enforced in memory, per process. Defaults: ingest and delete 60, search, get and
RAG 120 per tenant per minute, and 600 requests per client address per minute for every path
except `/health`. Several workers or replicas each enforce the limits separately, so put an
external limiter in front of a multi-replica deployment.

`GET /metrics` serves Prometheus text: requests by route *template* (never a document ID),
method and status, latency histograms, auth rejections and the key-cache size. Metrics are per
process, so run one uvicorn worker per container (the Docker image does) or aggregate at the
scraper.

See [docs/CTO_DEMO_SCRIPT.md](docs/CTO_DEMO_SCRIPT.md) for the full review flow, including the persistence check.

## Install Locally

```bash
git clone https://github.com/MysterionRise/encrypted-information-retrieval.git
cd encrypted-information-retrieval

python3.11 -m pip install -r requirements.txt
python3.11 -m pip install -e .
```

Optional dependencies for the CKKS and post-quantum modules in `encrypted_ir.research`:

```bash
python3.11 -m pip install -r requirements-research.txt
```

## Useful Commands

```bash
PYTHONPATH=src python3.11 -m pytest -q
python3.11 -m black --check src tests examples
python3.11 -m ruff check src tests examples
PYTHONPATH=src python3.11 -m mypy --disable-error-code redundant-cast src/encrypted_ir --ignore-missing-imports --no-strict-optional
python3.11 -m bandit -r src -ll -f screen
python3.11 -m build
python3.11 -m twine check dist/*
```

Generate a KMS-wrapped master key when AWS credentials and a KMS key are available:

```bash
python -m encrypted_ir.tools.generate_kms_master_key \
  --kms-key-id alias/encrypted-ir \
  --region us-east-1 \
  --environment prod
```

The key is wrapped with the KMS encryption context `application=encrypted-information-retrieval`,
`environment=<--environment>` and `purpose=app-master-key`, and the API unwraps it with the same
context, so set `--environment` to the `ENCRYPTED_IR_ENV` it will run under. A key generated before
this context existed must be regenerated. To make the context mandatory, add a condition to the
API role's `kms:Decrypt` permission:

```json
"Condition": {
  "StringEquals": {
    "kms:EncryptionContext:application": "encrypted-information-retrieval",
    "kms:EncryptionContext:environment": "prod",
    "kms:EncryptionContext:purpose": "app-master-key"
  }
}
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

- [docs/PORTFOLIO_EVIDENCE.md](docs/PORTFOLIO_EVIDENCE.md): dated evidence run, current status, limitations, and how to reproduce.
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md): what the code protects and leaks, with each known gap and its tracking issue.
- [docs/PORTFOLIO_CASE_STUDY.md](docs/PORTFOLIO_CASE_STUDY.md): CTO-facing case study.
- [docs/CTO_DEMO_SCRIPT.md](docs/CTO_DEMO_SCRIPT.md): five-minute review script.
- [docs/LEAKAGE_AND_ENDPOINTS.md](docs/LEAKAGE_AND_ENDPOINTS.md): API leakage map and production boundary.
- [docs/README.md](docs/README.md): documentation map and accuracy guidance.

The target-state section of `docs/ARCHITECTURE.md` and everything under `docs/archive/` are reference material, not claims about the current code. Treat executable tests, CI, and portfolio evidence as the source of truth.

## Security Notes

Encrypted retrieval always leaks something:

- deterministic tokens and blind indexes leak equality within their configured scope,
- keyword retrieval leaks query repetition, result sizes, and access patterns,
- the ORE prototype's comparison needs no key, so anyone holding ORE ciphertexts learns their total order,
- optional plaintext retrieval for RAG must be policy-gated and audited,
- local demo secrets are not a substitute for production KMS/HSM policy.

Use the project to discuss architecture and controls, not to claim compliance or audited cryptographic assurance.

## Roadmap

The roadmap lives in [docs/ROADMAP.md](docs/ROADMAP.md) and is tracked as GitHub issues grouped into three phases:

1. **v0.9.0 Honest prototype**: make every claim in code, docs, and CI verifiable. No behavioural change.
2. **v0.10.0 Durable path hardened**: fix the real bugs in the document/RAG path, remove demo-only routes, quarantine research modules.
3. **v1.0.0 Reviewed portfolio release**: cloud-free OIDC and KMS end-to-end evidence, benchmarks with provenance, a reviewer guide, and a tagged release.

Work beyond that (shared rate limiting, SIEM export, IaC, PIR/ORAM/TEE, vector retrieval, external audit) is listed in the roadmap as not planned, so no document implies it exists.

## License

MIT License. See [LICENSE](LICENSE).
