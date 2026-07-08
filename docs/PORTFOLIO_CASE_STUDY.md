# Portfolio Case Study

## Problem

Regulated AI systems need retrieval pipelines that can find relevant customer, risk, or operations documents without turning every search index into a plaintext data store. The hard part is not only encryption; it is making leakage, tenant boundaries, key lifecycle, auditability, and operational readiness explicit enough for engineering leadership to evaluate.

## What This Prototype Demonstrates

- Encrypted document storage with deterministic keyword-token retrieval.
- Tenant-scoped blind indexes for equality lookup without global cross-tenant correlation.
- ORE range comparisons for numeric workflows where order leakage is an accepted trade-off.
- Key creation, access, rotation, retired-key decryption, and audit trails.
- FastAPI, PostgreSQL, Alembic, readiness checks, Docker Compose evidence, and CI quality gates.
- A RAG boundary where search can return candidates without plaintext until an authorized retrieval step decrypts context.

## Architecture

```text
caller/API
  -> auth and tenant context
  -> encrypted document ingest
  -> key manager and storage backend
  -> encrypted document table + token table
  -> retrieval candidate ranking
  -> optional authorized plaintext release for RAG context
  -> sanitized audit records
```

The local demo has two paths. Docker Compose exercises the API and PostgreSQL workflow. `examples/portfolio_demo.py` exercises the same library primitives in-process for a fast screenshot and CI smoke path.

## AI/RAG Relevance

The project is not a chatbot and does not call a model. It focuses on the retrieval boundary a model would depend on:

- keep encrypted document bodies outside the keyword index,
- search over deterministic tokens,
- return document IDs and scores first,
- decrypt plaintext only for authorized context assembly,
- audit key, search, and decrypt operations.

That is a credible engineering slice for regulated RAG because it narrows the problem to the controls around retrieval, where sensitive data commonly leaks.

## Leakage Trade-Offs

- Blind indexes leak equality within a tenant and field.
- Keyword tokens leak query repetition, result sizes, and access patterns.
- ORE reveals order only through explicit comparisons, but those comparisons are still leakage.
- Returning plaintext for RAG is a policy decision and must be gated, logged, and minimized.

The right portfolio framing is that the prototype makes leakage visible and bounded. It should not be described as zero-leakage retrieval, PIR, ORAM, or production-certified cryptography.

## Operational Controls

- CI runs tests on Python 3.11 and 3.12.
- Formatting, ruff, bandit, and mypy are required gates.
- Packaging is verified through build and `twine check`.
- Readiness checks cover database, migration, auth posture, and key-provider posture.
- Audit records avoid plaintext, tokens, raw queries, and key material in the durable API workflow.

## Roadmap

1. Run production OIDC/JWKS and AWS KMS paths against real cloud tenants.
2. Add append-only audit export and SIEM integration.
3. Add deployment IaC, TLS, backup/restore, SLOs, alerting, and operational runbooks.
4. Add a policy layer for plaintext release into RAG context windows.
5. Replace or formally review prototype ORE/SSE primitives before production use.
6. Add vector retrieval only after the encrypted retrieval and audit boundary is explicit.
