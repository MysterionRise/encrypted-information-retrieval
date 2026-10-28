#!/usr/bin/env bash
# OIDC path in production mode, end to end, without a cloud account (issue #48).
#
# Keycloak is the identity provider (docker-compose.oidc.yml, realm in deploy/keycloak/) and
# moto server stands in for AWS KMS (docker-compose.kms.yml), because ENCRYPTED_IR_ENV=prod
# refuses to start without OIDC and KMS. The script:
#   1. checks that the API's Compose environment has no raw master key and no dev auth;
#   2. wraps a prod master key in moto, starts the API in prod, and waits for /ready with every
#      check true (in prod, key_provider is true only for a key unwrapped by KMS);
#   3. gets RS256 tokens from Keycloak with the password grant and checks their claims:
#        alice: tenant-a, read+write   carol: tenant-a, read   bob: tenant-b, read+write
#   4. alice ingests and retrieves; bob gets 404 on GET and DELETE and an empty retrieval;
#      carol may read but gets 403 on ingest; a token with a broken signature and the dev API
#      key both get 401;
#   5. restarts the API (KMS unwrap again), retrieves as alice, and verifies tenant-a's audit
#      chain.
#
# Usage: cp .env.example .env && ./scripts/oidc_smoke.sh
# Env:   COMPOSE_PROJECT_NAME (default encrypted-ir-oidc), COMPOSE_FILE (default base + KMS +
#        OIDC), RESULT_JSON (write a JSON summary there), KEEP_STACK=1 (leave it running).
# The realm's client secret and passwords are public demo values.
set -euo pipefail
cd "$(dirname "$0")/.."

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-encrypted-ir-oidc}"
export COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml:docker-compose.kms.yml:docker-compose.oidc.yml}"
RESULT_JSON="${RESULT_JSON:-}"
API_URL="${API_URL:-http://localhost:8000}"
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
ISSUER="http://keycloak:8080/realms/encrypted-ir"
TOKEN_URL="${KEYCLOAK_URL}/realms/encrypted-ir/protocol/openid-connect/token"
CLIENT_ID="encrypted-ir-demo"
CLIENT_SECRET="encrypted-ir-demo-secret"
DOC_ID="oidc-smoke-$(date +%s)-$$"
WORK="$(mktemp -d)"

cleanup() {
  local status=$?
  if [ "$status" -ne 0 ]; then
    docker compose --profile tools logs --no-color --tail 200 >&2 || true
  fi
  if [ "${KEEP_STACK:-0}" != "1" ]; then
    docker compose --profile tools down -v --remove-orphans > /dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# 1. The prod environment must not carry a raw master key or dev auth.
docker compose config --format json | python3 -c '
import json, sys
env = json.load(sys.stdin)["services"]["api"]["environment"]
assert env["ENCRYPTED_IR_ENV"] == "prod", env["ENCRYPTED_IR_ENV"]
assert env["ENCRYPTED_IR_DEV_AUTH_ENABLED"] == "false"
for name in ("ENCRYPTED_IR_MASTER_KEY_B64", "ENCRYPTED_IR_DEV_API_KEY", "ENCRYPTED_IR_JWT_SECRET"):
    assert name not in env, name + " is set for the prod API"
' || fail "the Compose environment of the prod API is wrong"
echo "config ok: prod, no raw master key, no dev auth"

# 2. KMS-wrapped prod master key, then the stack.
docker compose --profile tools down -v --remove-orphans > /dev/null 2>&1 || true
docker compose up -d postgres moto keycloak
line="$(docker compose run --rm -T kms-init --environment prod < scripts/kms_bootstrap.py)"
case "$line" in
  ENCRYPTED_IR_ENCRYPTED_MASTER_KEY_B64=?*) ;;
  *) fail "unexpected bootstrap output: ${line}" ;;
esac
export ENCRYPTED_IR_ENCRYPTED_MASTER_KEY_B64="${line#ENCRYPTED_IR_ENCRYPTED_MASTER_KEY_B64=}"
docker compose up -d api

wait_ready() {
  for _ in $(seq 1 90); do
    if curl -fsS "${API_URL}/ready" > "$WORK/ready.json" 2> /dev/null; then
      python3 - "$WORK/ready.json" <<'PY' || return 1
import json
import sys

ready = json.load(open(sys.argv[1]))
checks = ready["checks"]
assert ready["status"] == "ready" and all(checks.values()), ready
PY
      echo "API ready in prod mode: $(cat "$WORK/ready.json")"
      return 0
    fi
    sleep 2
  done
  curl -sS "${API_URL}/ready" >&2 || true
  fail "API did not become ready in 180s"
}
wait_ready

for _ in $(seq 1 90); do
  curl -fsS "${KEYCLOAK_URL}/realms/encrypted-ir/.well-known/openid-configuration" \
    > /dev/null 2>&1 && break
  sleep 2
done

# 3. Tokens, with their claims checked before the API sees them.
token() {
  local user="$1" tenant="$2" roles="$3"
  local response
  response="$(curl -fsS -X POST "$TOKEN_URL" \
    -d grant_type=password -d "client_id=${CLIENT_ID}" -d "client_secret=${CLIENT_SECRET}" \
    -d "username=${user}" -d "password=${user}-demo-password" -d scope=openid)" \
    || fail "Keycloak refused the password grant for ${user}"
  RESPONSE="$response" ISSUER="$ISSUER" TENANT="$tenant" ROLES="$roles" python3 - <<'PY'
import base64
import json
import os
import sys

access = json.loads(os.environ["RESPONSE"])["access_token"]
header, payload, _ = access.split(".")
claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
algorithm = json.loads(base64.urlsafe_b64decode(header + "=" * (-len(header) % 4)))["alg"]
audience = claims.get("aud")
audience = audience if isinstance(audience, list) else [audience]
problems = []
if algorithm != "RS256":
    problems.append(f"alg {algorithm}")
if claims.get("iss") != os.environ["ISSUER"]:
    problems.append(f"iss {claims.get('iss')}")
if "encrypted-ir" not in audience:
    problems.append(f"aud {audience}")
if claims.get("tenant_id") != os.environ["TENANT"]:
    problems.append(f"tenant_id {claims.get('tenant_id')}")
if sorted(claims.get("roles") or []) != sorted(os.environ["ROLES"].split(",")):
    problems.append(f"roles {claims.get('roles')}")
if problems:
    sys.exit("unexpected token claims: " + ", ".join(problems))
print(access)
PY
}
ALICE="$(token alice tenant-a read,write)" || fail "alice's token"
CAROL="$(token carol tenant-a read)" || fail "carol's token"
BOB="$(token bob tenant-b read,write)" || fail "bob's token"
echo "tokens ok: RS256, iss ${ISSUER}, aud encrypted-ir, tenant_id and roles as expected"

# 4. The API, as each user.
call() {
  # call METHOD PATH AUTH_HEADER [JSON_BODY]: prints the HTTP status, body in $WORK/body.json
  local method="$1" path="$2" auth="$3" body="${4:-}"
  local args=(-sS -o "$WORK/body.json" -w '%{http_code}' -X "$method" "${API_URL}${path}"
    -H "$auth")
  if [ -n "$body" ]; then
    args+=(-H 'Content-Type: application/json' -d "$body")
  fi
  curl "${args[@]}"
}
expect() {
  local want="$1" got="$2" what="$3"
  [ "$got" = "$want" ] || fail "${what}: expected HTTP ${want}, got ${got}: $(cat "$WORK/body.json")"
  echo "ok: ${what} -> ${got}"
}
retrieval_has_doc() {
  python3 - "$WORK/body.json" "$DOC_ID" <<'PY'
import json
import sys

candidates = json.load(open(sys.argv[1])).get("candidates", [])
match = [c for c in candidates if c.get("doc_id") == sys.argv[2]]
sys.exit(0 if match and "fraud risk controls" in (match[0].get("plaintext") or "") else 1)
PY
}
RAG='{"query":"fraud risk controls","top_k":25,"include_plaintext":true}'
INGEST="{\"doc_id\":\"${DOC_ID}\",\"content\":\"OIDC smoke document covering fraud risk controls for regulated RAG retrieval.\",\"metadata\":{\"source\":\"oidc-smoke\"}}"

expect 200 "$(call POST /v1/documents "Authorization: Bearer ${ALICE}" "$INGEST")" \
  "alice (tenant-a, write) ingests"
expect 200 "$(call POST /v1/rag/retrieve "Authorization: Bearer ${ALICE}" "$RAG")" \
  "alice retrieves"
retrieval_has_doc || fail "alice's retrieval does not contain ${DOC_ID} with its plaintext"
expect 404 "$(call GET "/v1/documents/${DOC_ID}" "Authorization: Bearer ${BOB}")" \
  "bob (tenant-b) gets tenant-a's document"
expect 200 "$(call POST /v1/rag/retrieve "Authorization: Bearer ${BOB}" "$RAG")" \
  "bob retrieves"
if retrieval_has_doc; then fail "bob's retrieval contains tenant-a's document"; fi
echo "ok: bob's retrieval does not contain tenant-a's document"
expect 404 "$(call DELETE "/v1/documents/${DOC_ID}" "Authorization: Bearer ${BOB}")" \
  "bob deletes tenant-a's document"
expect 403 "$(call POST /v1/documents "Authorization: Bearer ${CAROL}" \
  "{\"doc_id\":\"carol-${DOC_ID}\",\"content\":\"read-only users cannot ingest\"}")" \
  "carol (tenant-a, read only) ingests"
expect 200 "$(call POST /v1/rag/retrieve "Authorization: Bearer ${CAROL}" "$RAG")" \
  "carol retrieves"
retrieval_has_doc || fail "carol's retrieval does not contain tenant-a's document"
BROKEN="$(ALICE="$ALICE" python3 -c '
import os
header, payload, signature = os.environ["ALICE"].split(".")
i = len(signature) // 2
signature = signature[:i] + ("A" if signature[i] != "A" else "B") + signature[i + 1:]
print(".".join((header, payload, signature)))')"
expect 401 "$(call POST /v1/rag/retrieve "Authorization: Bearer ${BROKEN}" "$RAG")" \
  "a token with a broken signature"
expect 401 "$(call POST /v1/rag/retrieve "X-API-Key: local-demo-key" "$RAG")" \
  "the dev API key in prod"

# 5. A restart unwraps the master key through KMS again; the data is still there.
docker compose restart api
wait_ready
ALICE="$(token alice tenant-a read,write)" || fail "alice's token after the restart"
expect 200 "$(call POST /v1/rag/retrieve "Authorization: Bearer ${ALICE}" "$RAG")" \
  "alice retrieves after the restart"
retrieval_has_doc || fail "alice's retrieval after the restart does not contain ${DOC_ID}"
docker compose exec -T api python -m encrypted_ir.tools.export_audit --tenant tenant-a \
  > "$WORK/tenant-a.jsonl" 2> "$WORK/tenant-a.err" \
  || { cat "$WORK/tenant-a.err" >&2; fail "tenant-a's audit chain did not verify"; }
echo "audit ok: tenant-a's chain verified ($(wc -l < "$WORK/tenant-a.jsonl") entries)"

if [ -n "$RESULT_JSON" ]; then
  COMMIT="$(git rev-parse HEAD 2> /dev/null || echo "${GITHUB_SHA:-unknown}")" \
    python3 - "$RESULT_JSON" <<'PY'
import json
import os
import sys
from datetime import datetime, timezone

result = {
    "check": "oidc",
    "passed": True,
    "commit": os.environ["COMMIT"],
    "date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    "identity_provider": "Keycloak 26.8.1",
    "kms_emulator": "moto server 5.2.5",
    "steps": [
        "API in ENCRYPTED_IR_ENV=prod: no raw master key, no dev auth; /ready all true",
        "RS256 password-grant tokens with iss, aud, tenant_id and roles checked",
        "alice (tenant-a, read+write): ingest 200, retrieve finds the document",
        "bob (tenant-b): GET 404, DELETE 404, retrieve without the document",
        "carol (tenant-a, read): ingest 403, retrieve finds the document",
        "broken signature 401; dev API key 401",
        "API restart (KMS unwrap again); alice retrieves; tenant-a audit chain verified",
    ],
}
with open(sys.argv[1], "w") as out:
    json.dump(result, out, indent=2)
PY
fi
echo "oidc smoke test passed"
