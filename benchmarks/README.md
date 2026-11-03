# Benchmarks

There are two kinds of benchmark here. They answer different questions.

| | Retrieval benchmark | Primitive micro-benchmarks |
| --- | --- | --- |
| Question | How fast is the durable API path (encrypt, tokenize, audit, store, search, decrypt) on a real database? | Did a cryptographic primitive get slower? |
| Code | `python -m encrypted_ir.tools.benchmark_retrieval` | `benchmarks/test_core.py`, `benchmarks/test_research.py` (pytest-benchmark) |
| Output | `benchmarks/reports/<engine>/retrieval_<N>.json` and `.md`, committed | `benchmarks/results/latest.json`, not committed; medians compared with `benchmarks/baseline.json` |
| Run | `make bench-retrieval`, `make bench-retrieval-postgres` | `make bench`; in CI on pushes to master only (informational) |

## Retrieval benchmark

For each corpus size (100, 1,000 and 10,000 documents), a fresh tenant with a random master key:

1. ingests that many documents, each timed on its own;
2. times four read operations, each run 20 times untimed and then 200 times timed:
   - search with OR;
   - search with AND;
   - get-and-decrypt of one document;
   - RAG retrieval of the top 10 with plaintext.

Every operation reports n, mean, min, max and p50/p95/p99. p95 needs at least 20 samples and p99
at least 100, otherwise the report says "n/a". Searches return at most 100 results. The report
says how many documents match and how many results came back.

Each JSON file records:
- the commit, and whether the tree had uncommitted changes;
- the UTC time and the package version;
- the CPU model and logical core count, the OS and the Python version;
- the SQLAlchemy version and driver, and the database server version.

Each Markdown file is generated from its JSON; do not edit it by hand.
`scripts/render_evidence.py` builds the benchmark table in
[`docs/PORTFOLIO_EVIDENCE.md`](../docs/PORTFOLIO_EVIDENCE.md) from the same JSON.

### Reproduce

```bash
# In-memory SQLite, from a checkout with the dev dependencies installed:
make bench-retrieval

# The Compose PostgreSQL. The tool runs inside the API image, so the database stays unpublished:
cp .env.example .env
docker compose build api
make bench-retrieval-postgres
```

Pass `--documents`, `--rounds`, `--warmup` and `--search-limit` to the tool to change the run.
`scripts/bench_postgres.sh` reads `DOCUMENTS`, `ROUNDS` and `WARMUP` from the environment.

### What the numbers show, and what they do not

They show:
- what one request costs inside the service on the recorded machine, including the audit-chain
  append that every ingest commits with;
- how that cost changes with corpus size.

They do not show:
- **Throughput under load.** One process makes one call at a time.
- **HTTP and network cost.** There is no HTTP layer, no TLS and no network between client and
  service, and the database runs on the same machine.
- **Another machine.** The CPU in the header is the one that produced the file. CI runners and
  laptops differ by tens of percent from run to run.
- **Other queries or corpora.** Deterministic content and one query (`fraud controls`): every
  document mentions "controls" and one in five "fraud".
- **Leakage.** Speed says nothing about it. Retrieval uses deterministic keyword tokens, so the
  server sees token equality, query repetition, access patterns and result sizes (see
  [`docs/LEAKAGE_AND_ENDPOINTS.md`](../docs/LEAKAGE_AND_ENDPOINTS.md)).

## Primitive micro-benchmarks

`make bench` runs the pytest-benchmark suites and compares each median with
`benchmarks/baseline.json`. The comparison fails only when a median is more than 3x the baseline,
because shared CI runners vary too much for a tighter gate. `scripts/compare_benchmarks.py
--update` rewrites the baseline from a run you trust. The research suite needs the research
extras (`pip install -e '.[research]'`).
