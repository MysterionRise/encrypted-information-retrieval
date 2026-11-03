#!/usr/bin/env bash
# Docker Compose persistence smoke test.
#
# Replays the flow in docs/CTO_DEMO_SCRIPT.md against a running `docker compose up` stack:
# wait for /ready, ingest an encrypted document, retrieve it through /v1/rag/retrieve,
# restart the API container, and retrieve it again from PostgreSQL.
#
# Usage: cp .env.example .env && docker compose up -d --build && ./scripts/compose_smoke.sh
# Env:   API_URL (default http://localhost:8000), API_KEY (default local-demo-key),
#        COMPOSE_RESULT_JSON (write a JSON summary there; scripts/render_evidence.py reads it)
set -euo pipefail

API_URL="${API_URL:-http://localhost:8000}"
API_KEY="${API_KEY:-local-demo-key}"
DOC_ID="smoke-$(date +%s)-$$"

wait_ready() {
  for _ in $(seq 1 60); do
    if curl -fsS "${API_URL}/ready" > /dev/null 2>&1; then
      echo "API ready"
      return 0
    fi
    sleep 2
  done
  echo "API did not become ready in 120s" >&2
  curl -sS "${API_URL}/ready" >&2 || true
  return 1
}

retrieve_and_check() {
  local label="$1"
  local body
  body="$(curl -fsS -X POST "${API_URL}/v1/rag/retrieve" \
    -H 'Content-Type: application/json' \
    -H "X-API-Key: ${API_KEY}" \
    -d '{"query":"fraud risk controls","top_k":25,"include_plaintext":true}')"
  DOC_ID="$DOC_ID" BODY="$body" python3 - <<'PY'
import json
import os
import sys

doc_id = os.environ["DOC_ID"]
candidates = json.loads(os.environ["BODY"]).get("candidates", [])
ids = [c.get("doc_id") for c in candidates]
match = [c for c in candidates if c.get("doc_id") == doc_id]
if not match:
    sys.exit(f"{doc_id} not in candidates: {ids}")
if "fraud risk controls" not in (match[0].get("plaintext") or ""):
    sys.exit(f"plaintext for {doc_id} missing or wrong")
PY
  echo "retrieve ok (${label}): ${DOC_ID}"
}

wait_ready

curl -fsS -X POST "${API_URL}/v1/documents" \
  -H 'Content-Type: application/json' \
  -H "X-API-Key: ${API_KEY}" \
  -d "{\"doc_id\":\"${DOC_ID}\",\"content\":\"Smoke test document covering fraud risk controls for regulated RAG retrieval.\",\"metadata\":{\"source\":\"ci-smoke\"}}" \
  > /dev/null
echo "ingest ok: ${DOC_ID}"

retrieve_and_check "before restart"

docker compose restart api
wait_ready

retrieve_and_check "after restart"

if [ -n "${COMPOSE_RESULT_JSON:-}" ]; then
  COMMIT="$(git rev-parse HEAD 2> /dev/null || echo "${GITHUB_SHA:-unknown}")" \
    python3 - "$COMPOSE_RESULT_JSON" <<'PY'
import json
import os
import sys
from datetime import datetime, timezone

result = {
    "check": "compose",
    "passed": True,
    "commit": os.environ["COMMIT"],
    "date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    "steps": [
        "/ready (dev mode, PostgreSQL 16, one-shot migrate service)",
        "ingest with the dev API key; retrieve with plaintext",
        "docker compose restart api; retrieve again from PostgreSQL",
    ],
}
with open(sys.argv[1], "w") as out:
    json.dump(result, out, indent=2)
PY
fi
echo "compose smoke test passed"
