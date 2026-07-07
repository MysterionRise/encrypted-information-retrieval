# CTO Demo Script: Regulated RAG Retrieval Infrastructure

This 5-minute demo shows the project as security architecture for regulated AI
retrieval, not a toy encryption library.

Default path: Docker Compose only. No AWS account, KMS key, Cognito/Auth0/Okta
tenant, or external IdP is required for the portfolio demo.

## 1. Show the Deployment Shape

```bash
docker compose up --build
```

Call readiness:

```bash
curl http://localhost:8000/ready
```

Point out:
- PostgreSQL is the durable store.
- Alembic migrations run before API startup.
- Local demo auth is explicit and disabled in production mode.
- Production mode is designed for OIDC + AWS KMS.

## 2. Ingest an Encrypted Document

```bash
curl -X POST http://localhost:8000/v1/documents \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: local-demo-key' \
  -d '{"doc_id":"risk-001","content":"Quarterly fraud risk report for regulated RAG retrieval","metadata":{"source":"ctodemo"}}'
```

Explain:
- Content is encrypted with AES-GCM.
- Search tokens are deterministic HMAC values scoped by tenant keys.
- Key metadata is persisted separately from encrypted documents.

## 3. Retrieve RAG Candidates

```bash
curl -X POST http://localhost:8000/v1/rag/retrieve \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: local-demo-key' \
  -d '{"query":"fraud risk","top_k":3,"include_plaintext":true}'
```

Explain:
- The endpoint returns retrieval candidates for a downstream RAG system.
- It intentionally performs no LLM calls and no embedding generation.
- `include_plaintext` is audited because it exposes decrypted context.

## 4. Prove Persistence

```bash
docker compose restart api
```

Run the RAG retrieval request again. The document should still be returned
because Postgres stores ciphertext, keyword tokens, and encrypted key metadata.

## 5. Show Audit and Leakage Discipline

Open:
- `docs/LEAKAGE_AND_ENDPOINTS.md`
- `docs/DOCKER_COMPOSE_SMOKE_TEST.md`

Explain:
- The project explicitly documents token equality, query repetition, result
  size, and access-pattern leakage.
- Audit records include tenant, actor, operation, request ID, and result counts,
  but never plaintext, tokens, or key material.

## 6. Production Hardening Story

Summarize the production path:
- OIDC issuer/audience/JWKS verification replaces demo API keys.
- AWS KMS unwraps the app master key.
- Alembic migrations replace ad hoc schema creation.
- `/ready` gates deployments on DB, migration, auth, and key-provider posture.

Optional live-validation path if cloud credentials are available:
- Generate an AWS KMS-wrapped app master key with
  `python -m encrypted_ir.tools.generate_kms_master_key`.
- Configure a real OIDC issuer, audience, JWKS URL, tenant claim, and roles
  claim.
- Start the API with `ENCRYPTED_IR_ENV=prod` and verify `/ready` only reports
  ready after DB migrations, OIDC settings, and KMS settings are valid.
