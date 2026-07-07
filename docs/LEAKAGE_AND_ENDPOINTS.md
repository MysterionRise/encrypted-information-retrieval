# Leakage and Endpoint Map

This document ties each public API surface to the primitive it uses, the
expected leakage, and the production hardening path.

| Endpoint | Primitive / workflow | Expected leakage | Production risk | Mitigation |
| --- | --- | --- | --- | --- |
| `POST /v1/documents` | AES-GCM document encryption + HMAC keyword tokens | Document length, token count, ingest timing | Keyword frequency analysis over deterministic tokens | Scope keys per tenant, limit sensitive keywords, consider PIR/ORAM for high-sensitivity collections |
| `POST /v1/documents/search` | Tenant-scoped HMAC query tokens | Query repetition, matching doc IDs, result size, access pattern | Search/access-pattern inference | Audit searches, rate limit, pad results where required, use stronger SSE/PIR for sensitive collections |
| `GET /v1/documents/{doc_id}` | KeyManager-backed AES-GCM decrypt | Document access pattern, decrypt timing | Insider misuse or excessive decrypt access | OIDC roles, audit records, least-privilege policy, KMS-wrapped master key |
| `POST /v1/rag/retrieve` | Keyword-token retrieval over encrypted documents | Same as document search, plus optional plaintext disclosure to caller | RAG context exfiltration if caller is over-privileged | Require read role, audit `include_plaintext`, restrict downstream callers |
| `POST /v1/search/equality` | Blind index compatibility demo | Equality pattern within request-supplied index map | Caller controls index map; not durable service path | Use durable document workflow or integrate blind indexes into persisted records |
| `POST /v1/search/range` | Custom ORE prototype | Pairwise order comparison and access pattern | Custom crypto not externally audited | Treat as research demo; use vetted structured encryption or TEE before production |
| `POST /v1/search/keyword` | Legacy HMAC-token compatibility demo | Query repetition, result size, access pattern | Request-supplied tokens are demo-only | Use `/v1/documents/search` for durable workflow |

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
