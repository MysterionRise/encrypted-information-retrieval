#!/usr/bin/env bash
# Retrieval benchmark against the Compose PostgreSQL (issue #50).
#
# Runs encrypted_ir.tools.benchmark_retrieval inside the API image, on the same network as the
# Compose PostgreSQL, so the database stays unpublished. The stack runs as its own Compose
# project on a fresh volume and is removed on exit. Reports are written to
# benchmarks/reports/postgresql/ (retrieval_<N>.json and .md).
#
# Usage: cp .env.example .env && docker compose build api && ./scripts/bench_postgres.sh
# Env:   DOCUMENTS (default "100 1000 10000"), ROUNDS (200), WARMUP (20),
#        OUTPUT_DIR (benchmarks/reports/postgresql), COMPOSE_PROJECT_NAME (encrypted-ir-bench).
set -euo pipefail
cd "$(dirname "$0")/.."

export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-encrypted-ir-bench}"
export COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
OUTPUT_DIR="${OUTPUT_DIR:-benchmarks/reports/postgresql}"
read -r -a documents <<< "${DOCUMENTS:-100 1000 10000}"

commit="$(git rev-parse HEAD)"
dirty=()
if [ -n "$(git status --porcelain --untracked-files=no -- . ':!benchmarks/reports')" ]; then
  dirty=(--dirty)
fi

cleanup() {
  docker compose down -v --remove-orphans > /dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

docker compose up -d postgres
docker compose run --rm -T migrate
mkdir -p "$OUTPUT_DIR"
# DATABASE_URL is the one Compose gives the api service; expand it inside the container.
docker compose run --rm -T --no-deps --user "$(id -u):$(id -g)" \
  -v "$PWD/$OUTPUT_DIR:/out" api \
  sh -c 'exec python -m encrypted_ir.tools.benchmark_retrieval --database-url "$DATABASE_URL" "$@"' \
  benchmark --output-dir /out --documents "${documents[@]}" \
  --rounds "${ROUNDS:-200}" --warmup "${WARMUP:-20}" --commit "$commit" "${dirty[@]}"
echo "reports written to ${OUTPUT_DIR}"
