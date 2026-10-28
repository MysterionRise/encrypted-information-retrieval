# Leakage and Endpoint Map

This document ties each public API surface to the primitive it uses, the
expected leakage, and the production hardening path. The table lists every route the
API serves.

| Endpoint | Primitive / workflow | Expected leakage | Production risk | Mitigation |
| --- | --- | --- | --- | --- |
| `POST /v1/documents` | AES-GCM sealed content and metadata (bound to tenant, document and key) + HMAC keyword tokens | Document and metadata length, token count, ingest timing; the encrypting key's ID (row column and ciphertext header) | Keyword frequency analysis over deterministic tokens | Scope keys per tenant, limit sensitive keywords, consider PIR/ORAM for high-sensitivity collections |
| `POST /v1/documents/search` | Tenant-scoped HMAC query tokens | Query repetition, matching doc IDs, result size, access pattern | Search/access-pattern inference | Audit searches, rate limit, pad results where required, use stronger SSE/PIR for sensitive collections |
| `GET /v1/documents/{doc_id}` | KeyManager-backed AES-GCM decrypt | Document access pattern, decrypt timing | Insider misuse or excessive decrypt access | OIDC roles, audit records, least-privilege policy, KMS-wrapped master key |
| `DELETE /v1/documents/{doc_id}` | Hard delete of the ciphertext row and its token rows in one transaction | That a document ID existed (404 versus 204) to an authorized caller of the same tenant; delete timing | Deleted rows may persist in database backups and WAL until they age out | Write or admin role, audit event `document.delete`, backup retention policy |
| `POST /v1/rag/retrieve` | Keyword-token retrieval over encrypted documents | Same as document search, plus optional plaintext disclosure to caller | RAG context exfiltration if caller is over-privileged | Require read role, audit `include_plaintext`, restrict downstream callers |
| `GET /health` | None (unauthenticated) | Package version and process uptime | Version fingerprinting | Acceptable for a liveness probe; restrict at the network edge if needed |
| `GET /ready` | Database, migration, auth and key-provider checks (unauthenticated) | One pass/fail boolean per check and HTTP 503 when any fails. Exception text, Alembic revisions, auth mode and key source go to the server log only ([#41](https://github.com/MysterionRise/encrypted-information-retrieval/issues/41)) | Learning that a dependency is down | Restrict at the network edge if needed |
| `GET /docs`, `/redoc`, `/openapi.json` | Off unless `ENCRYPTED_IR_ENABLE_DOCS=true` | When enabled, the full route and schema list | Surface mapping | Leave off outside local development |
| `GET /metrics` | Prometheus text from a per-process registry; unauthenticated unless `ENCRYPTED_IR_METRICS_TOKEN` is set | Request counts and latency by route *template* (`/v1/documents/{doc_id}`), method and status; 401/403/429 counts by reason; the number of tenants with cached keys | Traffic-volume and timing analysis per route, and an estimate of active tenants | Set the metrics token or restrict the port at the network edge ([#43](https://github.com/MysterionRise/encrypted-information-retrieval/issues/43)) |

Error responses never carry exception text. Every 401 has the same body
(`{"detail": "Not authenticated"}`), whether the token is missing, expired, wrongly signed or names
an invalid tenant, and every 403 says only `Insufficient permissions`. The specific reason, the
route template and the caller's tenant (or `_system` when unauthenticated) go to an audit row
(`auth.failure`, `authz.failure` or `rate_limit.exceeded`). Each tenant, or each client address
when the caller is unauthenticated, gets at most 20 of those rows per minute, and the process at
most 120; `/metrics` counts every rejection and, by bound, how many were not audited.

Rate limits are per process. Each tenant has a limit per document operation, and every request
except `/health` also counts against a limit per client address, so unauthenticated floods,
`/ready` and `/metrics` are throttled too. A 429 carries `Retry-After` and reveals only that a
limit was reached.

Logs are JSON lines on stdout. Each request writes one access line with the method, route
template, status, latency, tenant ID and request ID; warnings and tracebacks carry the same
request ID. Document IDs, queries, plaintext and keys are not logged: values under sensitive key
names are dropped, strings are scanned for key-like base64, card numbers, SSNs and email
addresses, and SQL errors hide their bound parameters. Uvicorn's own access log, which prints raw
paths, is turned off in the Docker image. Logs do reveal which tenants are active and when.

The demo routes `/v1/encrypt`, `/v1/decrypt`, `/v1/search/{equality,range,keyword}` and
`/v1/keys*` were removed in [#36](https://github.com/MysterionRise/encrypted-information-retrieval/issues/36).
They held random per-process keys and shared nothing with the durable path. Blind-index and ORE
demos remain at library level in `examples/portfolio_demo.py`.

Metadata is encrypted with the document key since [#40](https://github.com/MysterionRise/encrypted-information-retrieval/issues/40)
and is returned decrypted only to callers of the owning tenant. Rows written before that keep
their metadata as plaintext JSON until the rotation tool
(`python -m encrypted_ir.tools.rotate_tenant_keys`, [#42](https://github.com/MysterionRise/encrypted-information-retrieval/issues/42)) re-encrypts them.

Each row also stores its keyword list, sealed under the document key, so rotation can rebuild the
search tokens. That reveals nothing new to a database reader, who already sees the token count.
During a rotation, a reader of the database can see which documents have moved to the new keys.
Searches compute tokens under every search key the tenant still has, so a query observer sees one
token per keyword per search key.

## Current Production Boundary

The main portfolio path is the durable document/RAG workflow. It uses
conservative primitives for confidentiality and tokenized retrieval, but it is
not zero-leakage encrypted search. For production-sensitive corpora, a reviewer
should explicitly approve the leakage budget above or require a stronger
retrieval construction.

## Audit Rules

Every audit row, for API events, rejected requests and key events alike, has one schema
(version 1): `schema_version`, `seq`, `tenant_id`, `timestamp`, `event_type`, `actor`,
`success`, `resource`, `details` and `request_id`. `details` passes through the same redaction
as logs, so rows never include plaintext, raw queries, search tokens, key material, or metadata
keys and values. They may include the tenant, actor, operation, request ID, result count and
document ID.

Each tenant's rows form an HMAC chain (ADR-017): a row stores the previous row's hash, and its
own hash is `HMAC-SHA256(audit key, prev_hash || canonical JSON of the entry)` under a key derived
from the app master key and the tenant ID.
`python -m encrypted_ir.tools.export_audit --tenant T` writes a tenant's chain as JSON lines,
verifies it from the first entry and prints the head hash.

When a row is written:

| Event | Audit row |
| --- | --- |
| Ingest, delete | Same transaction as the write. If the row cannot be written, the operation rolls back. |
| Search, get, RAG retrieve | Own transaction, after the read and before the response. If the row cannot be written, the request returns 500 without data. |
| Key create, rotate, deactivate, import | Same transaction as the key row, with the database backend. The file backend records no audit. |
| Failed operations, failed key reads, 401/403/429 | Own transaction, best effort: a failed write is logged, not retried. Rejections are rate-bounded as above. |

Audit rows are themselves visible to a database reader: they show which tenants and actors were
active and when, which document IDs were read or written, and how many results each search
returned. Anyone holding the master key can rewrite a chain consistently, and a database writer
can drop the newest rows and rewrite the head row; store exported head hashes where database
writers cannot change them and check them with `--check-head` ([#44](https://github.com/MysterionRise/encrypted-information-retrieval/issues/44)).
