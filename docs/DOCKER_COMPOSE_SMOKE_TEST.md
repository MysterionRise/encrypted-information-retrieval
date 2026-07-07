# Docker Compose Smoke Test

This smoke test verifies the PostgreSQL-backed encrypted document workflow used
for the portfolio RAG retrieval demo.

## 1. Start the Stack

```bash
docker compose up --build
```

Wait for the API to listen on `http://localhost:8000`.
The API container runs `alembic upgrade head` before starting Uvicorn.

## 2. Ingest an Encrypted Document

```bash
curl -X POST http://localhost:8000/v1/documents \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: local-demo-key' \
  -d '{"doc_id":"risk-001","content":"Quarterly fraud risk report for regulated RAG retrieval","metadata":{"source":"smoke-test"}}'
```

Expected: `200 OK` with `indexed_token_count` greater than zero.

## 3. Retrieve RAG Candidates

```bash
curl -X POST http://localhost:8000/v1/rag/retrieve \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: local-demo-key' \
  -d '{"query":"fraud risk","top_k":3,"include_plaintext":true}'
```

Expected: one candidate for `risk-001` with plaintext included.

## 4. Verify Persistence Across API Restart

Restart only the API container:

```bash
docker compose restart api
```

Run the retrieval request again. The same document should be returned because
PostgreSQL stores the encrypted document, keyword tokens, and key metadata, and
Compose provides a stable `ENCRYPTED_IR_MASTER_KEY_B64`.

## Notes

- `local-demo-key` is enabled only because `ENCRYPTED_IR_DEV_AUTH_ENABLED=true`
  in `docker-compose.yml`.
- Compose sets `ENCRYPTED_IR_AUTO_CREATE_TABLES=false`; schema changes are
  applied through Alembic migrations.
- This is a local demo workflow, not production authentication or secret
  management.
