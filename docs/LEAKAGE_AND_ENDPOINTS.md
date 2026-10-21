# Leakage and Endpoint Map

This document ties each public API surface to the primitive it uses, the
expected leakage, and the production hardening path. The table lists every route the
API serves.

| Endpoint | Primitive / workflow | Expected leakage | Production risk | Mitigation |
| --- | --- | --- | --- | --- |
| `POST /v1/documents` | AES-GCM document encryption + HMAC keyword tokens | Document length, token count, ingest timing | Keyword frequency analysis over deterministic tokens | Scope keys per tenant, limit sensitive keywords, consider PIR/ORAM for high-sensitivity collections |
| `POST /v1/documents/search` | Tenant-scoped HMAC query tokens | Query repetition, matching doc IDs, result size, access pattern | Search/access-pattern inference | Audit searches, rate limit, pad results where required, use stronger SSE/PIR for sensitive collections |
| `GET /v1/documents/{doc_id}` | KeyManager-backed AES-GCM decrypt | Document access pattern, decrypt timing | Insider misuse or excessive decrypt access | OIDC roles, audit records, least-privilege policy, KMS-wrapped master key |
| `POST /v1/rag/retrieve` | Keyword-token retrieval over encrypted documents | Same as document search, plus optional plaintext disclosure to caller | RAG context exfiltration if caller is over-privileged | Require read role, audit `include_plaintext`, restrict downstream callers |
| `GET /health` | None (unauthenticated) | Package version and process uptime | Version fingerprinting | Acceptable for a liveness probe; restrict at the network edge if needed |
| `GET /ready` | Database, migration, auth and key-provider checks (unauthenticated) | Raw exception text when a check fails, the current and head Alembic revisions, the auth mode (`dev` or `oidc`) and the master-key source (`aws-kms`, `raw-env` or `ephemeral-dev`) | Deployment reconnaissance; internals in error strings | Booleans plus a generic reason, details to the log: [#41](https://github.com/MysterionRise/encrypted-information-retrieval/issues/41) |
| `GET /metrics` | Process-global JSON counters (unauthenticated) | Request counts keyed by raw URL path, so the document IDs passed to `GET /v1/documents/{doc_id}` appear as keys; number of active tenants; error count; average latency | Document-ID and tenant-activity disclosure to anyone who can reach the port | Prometheus metrics with route-template labels and optional protection: [#43](https://github.com/MysterionRise/encrypted-information-retrieval/issues/43) |

The demo routes `/v1/encrypt`, `/v1/decrypt`, `/v1/search/{equality,range,keyword}` and
`/v1/keys*` were removed in [#36](https://github.com/MysterionRise/encrypted-information-retrieval/issues/36).
They held random per-process keys and shared nothing with the durable path. Blind-index and ORE
demos remain at library level in `examples/portfolio_demo.py`.

## Current Production Boundary

The main portfolio path is the durable document/RAG workflow. It uses
conservative primitives for confidentiality and tokenized retrieval, but it is
not zero-leakage encrypted search. For production-sensitive corpora, a reviewer
should explicitly approve the leakage budget above or require a stronger
retrieval construction.

## Audit Rules

Endpoint audit records must not include plaintext, raw queries, search tokens,
or key material. They may include tenant, actor, operation, request ID, result
count, document ID, and non-sensitive metadata keys.
