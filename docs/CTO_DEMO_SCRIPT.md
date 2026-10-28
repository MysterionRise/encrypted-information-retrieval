# CTO Demo Script: Regulated RAG Retrieval Infrastructure

This 5-minute demo shows the project as security architecture for regulated AI
retrieval, not a toy encryption library. Every claim it makes is mapped to its proof in
[REVIEW_GUIDE.md](REVIEW_GUIDE.md).

The whole HTTP surface is:
- `POST /v1/documents` and `POST /v1/documents/search`;
- `GET` and `DELETE /v1/documents/{doc_id}`;
- `POST /v1/rag/retrieve`;
- `/health`, `/ready` and `/metrics`;
- the docs routes, which are only served when enabled.

Default path: Docker Compose only. No AWS account, KMS key, Cognito/Auth0/Okta
tenant, or external IdP is required for the portfolio demo. Section 6 runs the
production key and auth paths locally too, against a KMS emulator and Keycloak.

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
- PostgreSQL is the durable store, and it is not published to the host.
- Alembic migrations run before API startup, in their own one-shot container.
- Local demo auth is explicit and refused in production mode.
- Production mode requires OIDC and AWS KMS; section 6 runs it locally.

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

## 5. Show Audit, Metrics and Leakage Discipline

Export and verify the tenant's audit chain from inside the API container (it uses the API's own
settings):

```bash
docker compose exec -T api python -m encrypted_ir.tools.export_audit --tenant local-demo
```

Expected: one JSON line per audited operation (`document.encrypt`, `rag.retrieve`, ...), and a
summary on stderr with `"verified": true` and the head `seq` and hash. The exit code is 0.
Editing any row in PostgreSQL makes the same command exit 2.

Show the metrics, then delete the document:

```bash
curl -s http://localhost:8000/metrics | grep 'route="/v1'
curl -i -X DELETE http://localhost:8000/v1/documents/risk-001 -H 'X-API-Key: local-demo-key'
curl -i http://localhost:8000/v1/documents/risk-001 -H 'X-API-Key: local-demo-key'
```

Expected:
- `/metrics` lines are keyed by route templates such as `/v1/documents/{doc_id}`, never by a
  document ID.
- The delete returns `204 No Content`, and the get that follows returns `404`.

Open:
- `docs/LEAKAGE_AND_ENDPOINTS.md`
- `docs/THREAT_MODEL.md`

Explain:
- The project explicitly documents token equality, query repetition, result
  size, and access-pattern leakage.
- Audit records include tenant, actor, operation, request ID, and result counts,
  but never plaintext, tokens, or key material. They form a per-tenant HMAC chain, so an
  edited, dropped or reordered row is detected on export.
- Tenant keys rotate with `python -m encrypted_ir.tools.rotate_tenant_keys --tenant local-demo`,
  which re-encrypts every document while the API keeps serving
  ([README](../README.md)).

## 6. Production Hardening Story

Summarize the production path:
- OIDC issuer/audience/JWKS verification replaces demo API keys.
- AWS KMS unwraps the app master key.
- Alembic migrations replace ad hoc schema creation.
- `/ready` gates deployments on DB, migration, auth, and key-provider posture, and reports
  only pass/fail booleans.
- Tokens must carry `exp`, `iat`, `aud`, `iss`, a valid tenant claim and roles. Every 401 has
  the same body; the reason goes to a rate-bounded audit row.

KMS path, locally, with no AWS account: `./scripts/kms_smoke.sh`. moto server stands in for AWS
KMS. The script wraps a master key with `generate_kms_master_key`, starts the API with
`ENCRYPTED_IR_KMS_PROVIDER=aws`, restarts it, and shows that a key wrapped for `dev` does not
unwrap under `ENCRYPTED_IR_ENV=test`. [KMS_DEPLOYMENT.md](KMS_DEPLOYMENT.md) has the IAM
policies and the CloudTrail setup for a real account.

### OIDC path, locally

Production mode, with no cloud account: `./scripts/oidc_smoke.sh`. Keycloak is the identity
provider and moto stands in for KMS, because `ENCRYPTED_IR_ENV=prod` refuses to start without
both. Show:
- The API's environment has no raw master key and no dev auth, and `/ready` reports every
  check `true`. In prod, `key_provider` is `true` only for a key unwrapped by KMS.
- Keycloak issues RS256 tokens whose `tenant_id` and `roles` claims the API reads.
- alice (tenant-a, read and write) ingests and retrieves.
- bob (tenant-b) gets 404 for alice's document and does not see it in retrieval.
- carol (tenant-a, read only) can retrieve but gets 403 on ingest.
- A token with a broken signature, and the dev API key, both get 401.
- After a restart (KMS unwraps the key again), the document is still there.

[OIDC_DEPLOYMENT.md](OIDC_DEPLOYMENT.md) maps the claims for Cognito, Auth0, Okta and Entra ID.

## Notes

- `local-demo-key` works only because `docker-compose.yml` sets
  `ENCRYPTED_IR_DEV_AUTH_ENABLED=true` and `.env` provides a 32-byte-plus
  `ENCRYPTED_IR_JWT_SECRET` and `ENCRYPTED_IR_DEV_API_KEY`. Dev auth is refused unless
  `ENCRYPTED_IR_ENV=dev`.
- Compose sets `ENCRYPTED_IR_AUTO_CREATE_TABLES=false`, so schema changes are applied only by
  the `migrate` service.
- This is a local demo workflow, not production authentication or secret management. The
  master key, database password and JWT secret in `.env.example` are public demo values.
