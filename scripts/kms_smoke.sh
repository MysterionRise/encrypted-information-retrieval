#!/usr/bin/env bash
# AWS KMS path, end to end, without an AWS account (issue #49).
#
# moto server stands in for AWS KMS (docker-compose.kms.yml). The script:
#   1. creates a KMS key and alias in moto and wraps a dev master key with the shipped tool
#      (encrypted_ir.tools.generate_kms_master_key: GenerateDataKey + encryption context);
#   2. starts the API with ENCRYPTED_IR_KMS_PROVIDER=aws and that wrapped key, then ingests,
#      retrieves, restarts the API and retrieves again (scripts/compose_smoke.sh);
#   3. proves the key came from KMS: the _system audit chain verifies and holds exactly two
#      key.unwrap rows, one per API start (in dev mode /ready alone cannot tell a KMS key from a
#      raw one);
#   4. proves the encryption context binds the key to its environment: the same wrapped key
#      fails to unwrap with ENCRYPTED_IR_ENV=test (InvalidCiphertextException).
#
# Usage: cp .env.example .env && ./scripts/kms_smoke.sh
# Env:   COMPOSE_PROJECT_NAME (default encrypted-ir-kms), COMPOSE_FILE (default base + KMS),
#        RESULT_JSON (write a JSON summary there), KEEP_STACK=1 (leave the stack running).
# The stack runs on a fresh volume and is removed on exit.
set -euo pipefail
cd "$(dirname "$0")/.."

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-encrypted-ir-kms}"
export COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml:docker-compose.kms.yml}"
RESULT_JSON="${RESULT_JSON:-}"
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

docker compose --profile tools down -v --remove-orphans > /dev/null 2>&1 || true
docker compose up -d postgres moto

line="$(docker compose run --rm -T kms-init --environment dev < scripts/kms_bootstrap.py)"
case "$line" in
  ENCRYPTED_IR_ENCRYPTED_MASTER_KEY_B64=?*) ;;
  *) echo "unexpected bootstrap output: ${line}" >&2; exit 1 ;;
esac
export ENCRYPTED_IR_ENCRYPTED_MASTER_KEY_B64="${line#ENCRYPTED_IR_ENCRYPTED_MASTER_KEY_B64=}"
echo "wrapped a dev master key under alias/encrypted-ir-master"

docker compose up -d api
./scripts/compose_smoke.sh

docker compose exec -T api python -m encrypted_ir.tools.export_audit --tenant _system \
  > "$WORK/system.jsonl" 2> "$WORK/system.err" \
  || { cat "$WORK/system.err" >&2; echo "the _system audit chain did not verify" >&2; exit 1; }
unwraps="$(python3 - "$WORK/system.jsonl" <<'PY'
import json
import sys

with open(sys.argv[1]) as rows:
    events = [json.loads(line) for line in rows if line.strip()]
print(sum(1 for e in events if e.get("event_type") == "key.unwrap" and e.get("success")))
PY
)"
if [ "$unwraps" != "2" ]; then
  echo "expected 2 key.unwrap audit rows (one per API start), found ${unwraps}" >&2
  exit 1
fi
echo "audit ok: _system chain verified with 2 key.unwrap rows"

set +e
mismatch="$(timeout 120 docker compose run --rm --no-deps -T \
  -e ENCRYPTED_IR_ENV=test -e ENCRYPTED_IR_DEV_AUTH_ENABLED=false api 2>&1)"
status=$?
set -e
if [ "$status" -eq 0 ] || [ "$status" -eq 124 ]; then
  echo "$mismatch" | tail -n 25 >&2
  echo "expected the API to fail at startup with the wrong environment, got exit ${status}" >&2
  exit 1
fi
if ! echo "$mismatch" | grep -q "InvalidCiphertextException"; then
  echo "$mismatch" | tail -n 25 >&2
  echo "expected InvalidCiphertextException from KMS Decrypt" >&2
  exit 1
fi
echo "context binding ok: a dev-wrapped key does not unwrap with ENCRYPTED_IR_ENV=test"

if [ -n "$RESULT_JSON" ]; then
  COMMIT="$(git rev-parse HEAD 2> /dev/null || echo "${GITHUB_SHA:-unknown}")" \
    python3 - "$RESULT_JSON" <<'PY'
import json
import os
import sys
from datetime import datetime, timezone

result = {
    "check": "kms",
    "passed": True,
    "commit": os.environ["COMMIT"],
    "date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    "emulator": "moto server 5.2.5",
    "steps": [
        "GenerateDataKey via encrypted_ir.tools.generate_kms_master_key (environment=dev)",
        "API start with ENCRYPTED_IR_KMS_PROVIDER=aws; ingest; retrieve",
        "API restart; retrieve",
        "_system audit chain verified; 2 key.unwrap rows",
        "ENCRYPTED_IR_ENV=test startup fails with InvalidCiphertextException",
    ],
}
with open(sys.argv[1], "w") as out:
    json.dump(result, out, indent=2)
PY
fi
echo "kms smoke test passed"
