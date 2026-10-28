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
- Audit records in a per-tenant HMAC chain, with an export tool that verifies it; they avoid plaintext, raw queries, tokens, and key material.
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

For the API and PostgreSQL workflow, copy the demo settings and start the stack:

```bash
cp .env.example .env    # public demo values; Compose refuses to start without them
docker compose up --build
```

A one-shot `migrate` service applies the Alembic migrations, then the API starts. PostgreSQL is
reachable only from those two services. The image runs as a non-root user (uid 10001), installs
its dependencies from the hash-pinned `requirements-docker.txt`, and includes boto3 for the AWS KMS
path.

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
| `ENCRYPTED_IR_TENANT_CLAIM` | `tenant_id` | Top-level token claim holding the tenant ID. |
| `ENCRYPTED_IR_ROLES_CLAIM` | `roles` | Top-level token claim holding the roles (`read`, `write`, `admin`; any other value means 403). |
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
and a non-empty roles claim; OIDC tokens also need `aud` and `iss`. Run the production auth path
locally, with Keycloak as the identity provider and the API in `ENCRYPTED_IR_ENV=prod`, using
`./scripts/oidc_smoke.sh`. [OIDC_DEPLOYMENT.md](docs/OIDC_DEPLOYMENT.md) maps the claims for
Cognito, Auth0, Okta and Entra ID.

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

KMS creates the key with `GenerateDataKey`, so the operator running the tool needs
`kms:GenerateDataKey` on that key, and only the wrapped copy is printed. The key is bound to the
KMS encryption context `application=encrypted-information-retrieval`,
`environment=<--environment>` and `purpose=app-master-key`, and the API unwraps it with the same
context, so set `--environment` to the `ENCRYPTED_IR_ENV` it will run under. A key generated before
this context existed must be regenerated. The IAM policies for the API role (`kms:Decrypt` only,
with that context required) and the operator role are in [`docs/iam/`](docs/iam/), with the
production steps and the CloudTrail setup in [KMS_DEPLOYMENT.md](docs/KMS_DEPLOYMENT.md).

Run the KMS path without an AWS account, with moto server standing in for AWS KMS:

```bash
cp .env.example .env
./scripts/kms_smoke.sh
```

Rotate a tenant's document and search keys while the API keeps serving. Use the same
`DATABASE_URL` and master-key settings as the API:

```bash
python -m encrypted_ir.tools.rotate_tenant_keys --tenant local-demo --batch-size 100
```

The tool:
- re-encrypts every document under new keys and rebuilds its search tokens;
- retires the old document key and destroys the old search key;
- prints a JSON report.

Exit codes:
- 0: complete.
- 1: configuration error, or a rotation already in progress.
- 2: some documents did not decrypt; nothing was retired.
- 3: not finished; continue with `--resume`. Use `--max-batches N` to stop after N batches on
  purpose.

The master key is rotated in AWS KMS by automatic rotation of the customer master key. KMS keeps
the old key material, so the wrapped master key in `ENCRYPTED_IR_ENCRYPTED_MASTER_KEY_B64` keeps
working unchanged.

Export and verify a tenant's audit chain, using the same `DATABASE_URL` and master-key settings as
the API:

```bash
python -m encrypted_ir.tools.export_audit --tenant local-demo --output audit.jsonl
```

It verifies the whole chain, prints the head (`head_seq`, `head_hash`) to stderr and exits 2 if the
chain is broken. Keep the head somewhere the database's writers cannot change, and pass it back as
`--check-head SEQ:HASH` on later exports to detect rows dropped from the end.

Run the retrieval benchmark, with provenance (commit, date, hardware, Python, driver and database
server) and p50/p95/p99, on in-memory SQLite or on the Compose PostgreSQL:

```bash
make bench-retrieval            # benchmarks/reports/sqlite-memory/
make bench-retrieval-postgres   # benchmarks/reports/postgresql/
```

[benchmarks/README.md](benchmarks/README.md) explains what the numbers do and do not show.

## Documentation

Read these first:

- [docs/REVIEW_GUIDE.md](docs/REVIEW_GUIDE.md): every claim in this README next to the test, CI step or run that proves it, the leakage you are asked to accept, and what is not claimed.
- [docs/PORTFOLIO_EVIDENCE.md](docs/PORTFOLIO_EVIDENCE.md): the CI evidence run of the release commit, benchmarks, current status, limitations, and how to reproduce.
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
