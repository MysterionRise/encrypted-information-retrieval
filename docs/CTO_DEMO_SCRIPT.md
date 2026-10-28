# CTO Demo Script: Regulated RAG Retrieval Infrastructure

This 5-minute demo shows the project as security architecture for regulated AI
retrieval, not a toy encryption library.

Default path: Docker Compose only. No AWS account, KMS key, Cognito/Auth0/Okta
tenant, or external IdP is required for the portfolio demo.

This script also serves as the persistence smoke test. It absorbs the former
`DOCKER_COMPOSE_SMOKE_TEST.md`, and each step lists its expected result.

## 1. Show the Deployment Shape

```bash
cp .env.example .env
docker compose up --build
```

Wait for the API to listen on `http://localhost:8000`. Compose first runs the one-shot `migrate`
service (`python -m encrypted_ir.migrations upgrade head`) and starts the API only after it exits
successfully. Then call readiness:

```bash
curl http://localhost:8000/ready
```

Expected: `{"status":"ready","checks":{"database":true,"migrations":true,"auth":true,"key_provider":true}}`.
Failure details go to the API log, not the response. The interactive docs are at
`http://localhost:8000/docs` because Compose sets `ENCRYPTED_IR_ENABLE_DOCS=true`.

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

Expected: `200 OK` with `indexed_token_count` greater than zero.

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

Expected: one candidate for `risk-001` with plaintext included.

Explain:
- The endpoint returns retrieval candidates for a downstream RAG system.
- It intentionally performs no LLM calls and no embedding generation.
- `include_plaintext` is audited because it exposes decrypted context.

## 4. Prove Persistence

```bash
docker compose restart api
```

Run the RAG retrieval request again. The document should still be returned
because Postgres stores ciphertext, keyword tokens, and encrypted key metadata,
and Compose provides a stable `ENCRYPTED_IR_MASTER_KEY_B64`.

## 5. Show Audit and Leakage Discipline

Open:
- `docs/LEAKAGE_AND_ENDPOINTS.md`
- `docs/THREAT_MODEL.md`

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
- `/ready` gates deployments on DB, migration, auth, and key-provider posture, and reports
  only pass/fail booleans.
- Tokens must carry `exp`, `iat`, `aud`, `iss`, a valid tenant claim and roles. Every 401 has
  the same body; the reason goes to a rate-bounded audit row.

Optional live-validation path if cloud credentials are available:
- Generate an AWS KMS-wrapped app master key with
  `python -m encrypted_ir.tools.generate_kms_master_key --environment prod`. It is wrapped with
  the encryption context `application`, `environment` and `purpose`; the README shows the IAM
  condition that makes that context mandatory for `kms:Decrypt`.
- Configure a real OIDC issuer, audience, JWKS URL, tenant claim, and roles
  claim.
- Start the API with `ENCRYPTED_IR_ENV=prod` and verify `/ready` only reports
  ready after DB migrations, OIDC settings, and KMS settings are valid.

## Notes

- `local-demo-key` works only because `docker-compose.yml` sets
  `ENCRYPTED_IR_DEV_AUTH_ENABLED=true` and `.env` provides a 32-byte-plus
  `ENCRYPTED_IR_JWT_SECRET` and `ENCRYPTED_IR_DEV_API_KEY`. Dev auth is refused unless
  `ENCRYPTED_IR_ENV=dev`.
- Compose sets `ENCRYPTED_IR_AUTO_CREATE_TABLES=false`, so schema changes are applied only by
  the `migrate` service.
- This is a local demo workflow, not production authentication or secret management. The
  master key, database password and JWT secret in `.env.example` are public demo values.
