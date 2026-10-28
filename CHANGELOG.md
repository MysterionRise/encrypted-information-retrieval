# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). From 1.0.0, a breaking change
to the public surface needs a major version. The public surface is:
- the HTTP API under `/v1`, plus `/health`, `/ready` and `/metrics`;
- the `ENCRYPTED_IR_*` settings;
- the command-line tools in `encrypted_ir.tools` and `python -m encrypted_ir.migrations`;
- the database schema, which changes only through Alembic migrations;
- the names exported by the `encrypted_ir` package.

`encrypted_ir.research` is excluded: its prototypes may change in any release. Before 1.0.0,
minor versions could contain breaking changes.

The roadmap that drives these versions is in [docs/ROADMAP.md](docs/ROADMAP.md):
`0.9.0` closes Phase 0 (issue #26), `0.10.0` closes Phase 1 (issue #27), and
`1.0.0` closes Phase 2 (issue #28).

## [Unreleased]

### Security

- **The Docker image runs as a non-root user and can start the KMS path** (#45). It runs as
  uid 10001 and installs the hash-pinned `requirements-docker.txt` into a digest-pinned base
  image. It now includes boto3, so the AWS KMS production path starts from the shipped image; CI
  runs it against a dead KMS endpoint to show it gets as far as calling KMS.
- **Compose no longer hard-codes secrets** (#45). The database password, master key, dev API key
  and JWT secret come from `.env` (copy `.env.example`, whose values are public demo values), and
  Compose refuses to start if one is missing. PostgreSQL is no longer published on host port 5432.
- **Key rotation re-encrypts documents** (#42, ADR-018). `python -m
  encrypted_ir.tools.rotate_tenant_keys --tenant T` rotates a tenant's document and search keys
  while the API serves:
  - It creates successor keys, then re-encrypts every document in resumable batches with a
    compare-and-swap write.
  - It rebuilds each document's search tokens from a keyword list now sealed at ingest.
  - It then retires the old document key and destroys the old search key, clearing its bytes.
  - Legacy rows are upgraded to the sealed format.
  - Concurrency: an ingest that races a rotation retries with fresh keys, a search that races
    one runs again, and a second rotation of the same tenant is refused. A document that does not
    decrypt blocks retirement and is reported.
  - Documents ingested with explicit keywords before this release keep their old search key,
    which stays searchable, until they are ingested again; the tool reports them.
- `generate_kms_master_key` lets KMS create the master key with `GenerateDataKey` instead of
  generating it locally and calling `Encrypt` (#42). The operator now needs
  `kms:GenerateDataKey`. Rotate the master key with KMS-side rotation of the customer master key.
- **Audit rows form a tamper-evident chain** (#44, ADR-017). Every row has one schema and an
  `entry_hash = HMAC-SHA256(audit_key, prev_hash || canonical_json(entry))`, where `audit_key` is
  derived from the app master key per tenant; a head row per tenant records the last `seq` and
  hash. Editing, deleting, reordering or moving rows between tenants is detected.
  `python -m encrypted_ir.tools.export_audit --tenant T` exports a chain as JSON lines, verifies
  it from the first row, prints the head and exits 2 if it is broken; `--check-head SEQ:HASH`
  checks a head saved from an earlier export. Whoever holds the master key can still rewrite a
  chain, so keep exported heads where database writers cannot change them.
- **Writes and their audit rows commit together** (#44). Ingest, delete and key changes append
  their audit row in the same transaction, so an operation whose audit row fails is rolled back.
  Search, get and RAG retrieve append before the response and return 500 if they cannot. Failed
  key reads are audited too. `delete_document` deletes the document row before its tokens.
- Rejected-request audits are bounded per tenant or client address (20 per minute) with a process
  cap (120 per minute), instead of 60 per minute per process, so one noisy client can no longer
  use up the whole allowance (#44). `encrypted_ir_security_audit_dropped_total` has a `limit`
  label (`per_source` or `total`).
- **Rate limiting covers unauthenticated requests and has bounded state** (#47). Every request
  except `/health` counts against a per-client-address limit (600 per minute by default), checked
  before authentication, so floods of bad tokens, `/ready` and `/metrics` are throttled. Buckets
  that have refilled are dropped and each operation keeps at most 10,000, so rotating tenant IDs
  or client addresses can no longer grow memory without bound. Behind a reverse proxy, set
  `ENCRYPTED_IR_TRUSTED_PROXIES` so the client address comes from `X-Forwarded-For`; the header is
  ignored from any other peer.
- **`/metrics` no longer leaks document IDs** (#43). It served JSON keyed by the raw request
  path, so every `GET /v1/documents/{doc_id}` added the document ID as a key, and kept an
  unbounded set of active tenants. It now serves Prometheus text whose route label is the route
  template, with bounded method and status labels. `ENCRYPTED_IR_METRICS_TOKEN` optionally
  requires a bearer token.
- Logs are redacted by one shared policy, `encrypted_ir.redaction.redact` (#43): sensitive key
  names are dropped even when nested, bytes are never written, key-like base64 and Luhn-valid
  card numbers are masked, and exception tracebacks are redacted too. Lower-case hex digests and
  millisecond timestamps are no longer mistaken for keys and cards. SQL errors hide their bound
  parameters (`hide_parameters=True`), so a failed statement cannot print ciphertext or tokens.
- The Docker image runs uvicorn with `--no-access-log`; its access log printed raw paths with
  document IDs (#43).

- **Tokens are fully validated** (#41). Dev and OIDC tokens must carry `exp` and `iat` (30 s
  leeway, `ENCRYPTED_IR_JWT_LEEWAY_SECONDS`); OIDC tokens also need `aud` and `iss`, and are
  accepted only with an allowlisted asymmetric algorithm (`ENCRYPTED_IR_OIDC_ALGORITHMS`, default
  `RS256`; `PS256` and `ES256` allowed, `HS*` and `none` refused at startup). The tenant claim must
  be a string matching `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`, so `_system` and other
  underscore-prefixed tenants are rejected, and the roles claim is required in every mode
  instead of defaulting to `read` under dev auth.
- **Errors no longer echo internals** (#41). Every 401 returns `{"detail": "Not authenticated"}`
  and every 403 `Insufficient permissions`; `ValueError` and `KeyError` responses carry generic
  messages. The specific reason goes to an audit row (`auth.failure`, `authz.failure`,
  `rate_limit.exceeded`) under the caller's tenant, or `_system` when unauthenticated, limited
  to 60 rows per minute per process. `/metrics` counts every 401, 403 and 429.
- **`/ready` returns booleans only** (#41); exception text, migration revisions, auth mode and
  key source go to the log.
- `X-Request-ID` is echoed only if it is 1 to 64 characters of `[A-Za-z0-9._-]`; anything else
  is replaced with a UUID (#41).
- Request bodies are limited by actual size, including chunked bodies without `Content-Length`;
  an invalid `Content-Length` returns 400 (#41). The limit is `ENCRYPTED_IR_MAX_BODY_BYTES`.
- CORS allows only `GET`, `POST` and `DELETE` and a fixed header list, and never sends
  credentials with a `*` origin; `*` is refused in `prod` (#41).
- Settings repr no longer shows the master key, JWT secret or dev API key (#41).
- **Ciphertexts are bound to their context** (#40, ADR-007). Document content and metadata are
  sealed in a versioned header (`version || algorithm || key_id || nonce`), and the AES-GCM
  associated data covers the header, the tenant, the document ID and the purpose (content or
  metadata). Swapping ciphertexts between rows, tenants or purposes, editing the header, or
  pointing a row at another key now fails to decrypt instead of returning the wrong plaintext.
  Integrity failures return a generic 500 and write a failure audit row.
- **Document metadata is encrypted** (#40). New rows store it sealed in `encrypted_metadata` and
  leave `metadata_json` empty. Search, get and RAG return it decrypted to the owning tenant.
  Audit rows no longer record metadata key names.
- **Wrapped tenant keys are bound** to their tenant, key ID, key type and version (#40). A wrapped
  key copied to another tenant, or with edited metadata, no longer unwraps, and such a row no
  longer breaks the other keys of the tenant.
- **AWS KMS calls carry an encryption context** (#40): `application`, `environment` and
  `purpose`, plus a pinned `KeyId` on `Decrypt`. IAM can require the context with
  `kms:EncryptionContext:*` conditions; the README shows one.

### Removed

- The mean-only retrieval reports in `benchmarks/reports/` and the archived report template
  the tool never filled (#50). Latency figures in `docs/DECISIONS.md` that were never measured
  are gone; figures from published work are kept and labelled as such.
- `requirements-api.txt`, replaced by the generated, hash-pinned `requirements-docker.txt`
  (#45).
- `encrypted_ir.key_rotation` (`KeyRotationManager`, `RotationPolicy`, `RotationProgress`,
  `rotate_kek`) and `KeyManager.rotate_key` (#42). The rotation tool is now the only rotation
  path. `rotate_kek` never persisted the re-wrapped master key, and nothing called
  `KeyRotationManager`'s re-encryption. Use `KeyManager.begin_rotation` in library code.
- `encrypted_ir.audit.AuditLogger` and its helpers, `KeyManager.get_audit_log()` and the
  in-memory key audit log, `StorageBackend.save_audit_entry`/`load_audit_log`, and the file
  backend's `audit.jsonl` (#44). Key events are written by `DatabaseStorageBackend.save_key(...,
  audit=...)` and `append_audit`; the file backend records no audit.
- `VersionedBlob` and `KeyRotationManager.resolve_key_for_blob` (#40). Nothing used them, and the
  32-bit key hash could not tell versioned blobs from legacy ones reliably. The document header
  in `encrypted_ir.document_crypto` replaces them.
- `encrypted_ir.order_preserving` (OPE) and the `TransactionProcessing` and `FraudDetection` use
  cases built on it (#37). This OPE was decryptable without the key: `plaintext = ciphertext //
  (2**32 + 1)`. ORE is not a drop-in replacement, because this repository's ORE prototype also
  reveals total order.
- The demo API routes `POST /v1/encrypt`, `POST /v1/decrypt`, `POST /v1/search/equality`,
  `POST /v1/search/range`, `POST /v1/search/keyword`, `GET /v1/keys` and `POST /v1/keys/rotate`
  (#36). They held random per-process keys in module globals, so their data did not survive a
  restart, differed between workers and shared nothing with the stored documents. The API now
  serves only the durable document routes plus `/health`, `/ready` and `/metrics`.
  Library-level blind-index and ORE demos remain in `examples/portfolio_demo.py`.
- The in-memory API-key registry (`register_api_key`, `clear_api_keys`), which only tests used,
  and the request and response models of the removed routes.

### Fixed

- `alembic_config(url)` failed on any URL containing `%`, such as a URL-encoded password or a
  query option, because Alembic's config treats `%` as interpolation (#46). It is escaped now.
- AND search returned nothing once a tenant had more than one search key, for example after a
  search-key rotation (#39). The score is now the number of distinct query keywords matched, and
  AND requires all of them, whichever key produced each token. Destroyed search keys are skipped.
- Key reads wrote to the database (#39). Every `get_key` rewrote the key row (delete, then insert)
  and inserted an audit row, so a RAG request returning 25 documents with plaintext made more
  than 150 writes, and concurrent reads could collide. Reads now count accesses in memory only, unless `audit_reads=True`. Saving a key
  updates its row in place.
- The per-tenant key cache never reloaded (#39). A worker that cached a tenant before another
  worker created its keys created its own keys and could not read the other worker's documents.
  The cache is now a bounded LRU with a 5-minute TTL, refreshes from the database before each
  ingest and search, and loads unknown key IDs on demand.
- The active key was chosen by random key-ID order (#39). It is now the newest active key by
  creation time.
- A duplicate `doc_id` returned 400 with the tenant ID in the message, and a concurrent duplicate
  returned 500 (#39). Both return 409 with a generic message.
- Keyword extraction filtered stop words and short words before stripping punctuation, so `The,`
  and `(or)` were indexed and `...` became an empty keyword (#39). Punctuation is now stripped
  first, empty keywords are never produced, and explicit keywords are normalized the same way as
  queries (`AI,` matches `ai`).
- `/v1/rag/retrieve` with `include_plaintext` failed with 404 when a candidate was deleted
  between search and decrypt (#39). The candidate is now skipped.

### Changed

- Version `1.0.0`, with the classifier `Development Status :: 4 - Beta` (the research modules
  remain prototypes) (#51). This file now says what Semantic Versioning covers from 1.0.0: the
  HTTP API, the settings, the CLI tools, the migrations and the package exports;
  `encrypted_ir.research` is excluded.
- **The whole test suite runs on PostgreSQL in CI, in parallel** (#46). Each pytest-xdist worker
  gets its own migrated schema, truncated after every test; API tests use the `app_factory` and
  `db_url` fixtures, which dispose engines. Any 500 response fails a test unless it is marked
  `allow_500`. Logging configuration and the correlation ID are restored after every test. The
  coverage job has a PostgreSQL service too. `pytest-xdist` is added to `requirements-ci.in`.
- Benchmarks moved to `benchmarks/` (outside `testpaths`), so the unit suite no longer runs or
  calibrates them (#46). The master-only benchmarks job compares medians with
  `benchmarks/baseline.json` through `scripts/compare_benchmarks.py` (3x slowdown fails; the job
  is informational).
- **Breaking: migrations are a separate step** (#45). The image's command starts only uvicorn;
  Compose runs `python -m encrypted_ir.migrations upgrade head` in a one-shot `migrate` service
  and starts the API after it succeeds. Other deployments must run that command before starting
  the API.
- **Breaking: Compose needs a `.env`** (#45): `cp .env.example .env` before `docker compose up`.
- **Breaking: `alembic.ini` names no database** (#45). The `alembic` CLI migrates the database in
  `DATABASE_URL`, and a URL passed to `alembic_config(url)` now wins over `DATABASE_URL`. Before,
  the environment won, so code that passed a URL could migrate a different database.
- The `aws` extra requires `boto3>=1.28.57`, the first release that reads
  `AWS_ENDPOINT_URL_KMS` (#45).
- **Breaking: migration 0005** (#42). Run `alembic upgrade head`. It adds:
  - `encrypted_ir_documents.encrypted_keywords`;
  - indexes on `(tenant_id, encryption_key_id)` and `(tenant_id, search_key_id)`;
  - `encrypted_ir_key_rotations`.

  `StorageBackend` implementations must provide `save_keys`. `refresh()` loads destroyed keys'
  metadata without unwrapping them.
- **Breaking: migration 0004 and one audit schema** (#44). Run `alembic upgrade head`. Audit rows
  gain `schema_version`, `event_type`, `actor`, `request_id`, `success`, `seq`, `prev_hash` and
  `entry_hash`, and `encrypted_ir_audit_chain_heads` is new. Rows written before the migration
  keep NULL chain columns and are reported as unchained by the export tool. Key events now use
  the same schema as API events, with event types `key.create`, `key.read`, `key.rotate`,
  `key.deactivate`, `key.import` and `key.unwrap`; `AuditEventType` lists only the event types
  that are written (`SEARCH_KEYWORD`, `DECRYPT` and others are gone).
- **Breaking: the rate limiter lives on `app.state.rate_limiter`** (#47). The module-level
  limiter and `set_rate_limiter` are removed; `get_rate_limiter` reads the app's limiter. The
  limiter uses GCRA (one timestamp per key, exact `Retry-After`) instead of lists of
  timestamps; a limit of N per window still allows a burst of N.
- The Docker image runs uvicorn with `--no-proxy-headers`; the app handles proxy headers itself
  (#47).
- The architecture doc no longer shows a Redis cache and several API replicas; rate limits and
  metrics are per process, and the docs say so (#47).

- **Breaking: `/metrics` is Prometheus text** (#43), not JSON. The JSON fields
  (`request_count`, `requests_by_endpoint`, `unauthorized_count` and the rest) are replaced by
  `encrypted_ir_http_requests_total{route,method,status}`,
  `encrypted_ir_http_request_duration_seconds{route,method}`,
  `encrypted_ir_auth_rejections_total{status,reason}`,
  `encrypted_ir_security_audit_dropped_total` and `encrypted_ir_key_cache_tenants`. Each app has
  its own registry, so metrics are per process. `EncryptionMetrics` is rebuilt around these;
  its unused counters and gauges are removed, as are `MetricsResponse` and
  `api.routes.admin.reset_metrics`.
- Unhandled exceptions now pass through the request middleware (#43): the 500 response carries
  `X-Request-ID` and `X-Response-Time-Ms`, is counted, and its traceback is logged with the
  request ID. The body message is `Internal server error`.
- The request middleware is pure ASGI instead of `BaseHTTPMiddleware` (#43).
- `StructuredFormatter` timestamps are UTC ISO 8601 with milliseconds; the old format printed a
  literal `%f` and local time labelled `Z` (#43). `correlation_id` is `null` outside a request
  instead of a fresh random ID. `LoggingConfig` logs to stdout by default and can route other
  loggers (`uvicorn.error`) through the same JSON handler.
- File-based SQLite engines wait up to 30 s for locks and use WAL (#43).

- **Breaking: dev auth is off by default** (#41). `ENCRYPTED_IR_DEV_AUTH_ENABLED` defaults to
  `false`, is refused unless `ENCRYPTED_IR_ENV=dev`, and needs `ENCRYPTED_IR_JWT_SECRET` of at
  least 32 bytes; there is no built-in secret any more. The dev API key works only when
  `ENCRYPTED_IR_DEV_API_KEY` is set. `docker-compose.yml` sets all three, so the Compose demo is
  unchanged.
- **Breaking: `/docs`, `/redoc` and `/openapi.json` are off by default** (#41). Set
  `ENCRYPTED_IR_ENABLE_DOCS=true` to serve them; Compose does.
- **Breaking: `/ready` response shape** (#41). `checks` maps `database`, `migrations`, `auth`
  and `key_provider` to booleans instead of objects with `ok`, `error`, `mode` and `source`.
- Auth configuration is read only from `EncryptedIRSettings` at app startup (#41). Importing
  `encrypted_ir.api` no longer reads the environment, warns, or raises. If the app has no auth
  config, every request is rejected.
- Document routes, `/ready` and the auth dependencies are plain `def` functions, so FastAPI runs
  them in its thread pool; a slow database or JWKS fetch no longer blocks `/health` and
  `/metrics` (#41). The rate limiter is guarded by a lock.
- **Breaking for KMS deployments:** an `ENCRYPTED_IR_ENCRYPTED_MASTER_KEY_B64` created before
  #40 was wrapped without an encryption context and no longer unwraps. Regenerate it with
  `python -m encrypted_ir.tools.generate_kms_master_key --environment <ENCRYPTED_IR_ENV>`, or
  re-encrypt the existing blob with `aws kms re-encrypt` and the new destination context.
- New documents use the `aes-256-gcm/v1` format; `POST /v1/documents` reports it as
  `algorithm`. Rows written earlier (`aes-gcm`) and keys wrapped earlier stay readable. Alembic
  `20261021_0003` adds the `encrypted_metadata` column; run `alembic upgrade head`.
- The never-set `encrypted_ir_documents.deleted` column is dropped (Alembic `20261021_0002`).
  Deletes are hard deletes. Run `alembic upgrade head`.
- **Breaking: research modules moved** (#37). Update imports as follows:

  | Before | After |
  | --- | --- |
  | `encrypted_ir.ore` / `from encrypted_ir import ORE` | `encrypted_ir.research.ore` |
  | `encrypted_ir.fpe` / `FF1`, `FormatPreservingEncryption` | `encrypted_ir.research.fpe` |
  | `encrypted_ir.homomorphic` / `BasicHomomorphicEncryption` | `encrypted_ir.research.homomorphic` |
  | `encrypted_ir.post_quantum` / `MLKEM`, `MLDSA`, `HybridKEM`, `PostQuantumEncryption` | `encrypted_ir.research.post_quantum` |
  | `encrypted_ir.differential_privacy` and its seven classes | `encrypted_ir.research.differential_privacy` |
  | `encrypted_ir.use_cases` | `encrypted_ir.research.use_cases` |
  | `encrypted_ir.searchable.ForwardPrivateSSE`, `BackwardPrivateIndex` | `encrypted_ir.research.forward_private_sse` |

  The top-level package no longer sets the CKKS and post-quantum names to `None` when their
  optional dependencies are missing. Importing those modules without the `research` extra raises
  an `ImportError` that names the extra.
- **Breaking: blind-index values change** (#37). Field keys are now derived from a
  length-prefixed context (`encrypted-ir/blind-index/v2`, tenant, field), so tenant `a:b` with
  field `c` no longer shares a key with tenant `a` and field `b:c`. Indexes created by earlier
  versions must be rebuilt. Blind indexes are not stored by the durable document path.
- **Breaking: `BlindIndexSearch.index_records` returns `dict[str, list[str]]`** (#37), mapping each
  index to every record with that value. Previously records sharing a value overwrote each other
  and `search` returned at most one of them. `BlindIndexConfig` now rejects an `output_length`
  outside 8 to 32 bytes and an unknown `unicode_normalize` form; `None` disables normalization.
- The ORE prototype's `ALGORITHM` identifier is now `ore-clww-prototype`. Ciphertexts are unchanged.
- Tests no longer hide `DeprecationWarning`s: the global filter in `pyproject.toml`, CI and the
  Makefile existed only for OPE.
- The coverage CI job installs the research extras, so the prototypes' tests count toward the
  coverage floor.
- The package version is now `0.9.0` with the classifier `Development Status :: 3 - Alpha`,
  matching the project's prototype status. The earlier `1.0.0` string was never tagged or released.
- The version has one source, `encrypted_ir.__version__`. `pyproject.toml`, the FastAPI app,
  `/health`, `make info` and the tests read it from there.
- The build requires `setuptools>=77`, which the SPDX string `license = "MIT"` needs.
- GitHub Actions bumped by Dependabot: `actions/checkout` v6, `actions/setup-python` v6,
  `actions/upload-artifact` v7, `codecov/codecov-action` v6.
- Development dependency floors bumped by Dependabot: ipython, isort, myst-parser,
  pytest-timeout, sphinx, types-setuptools.

### Added

- A reviewer guide and release evidence from CI (#51):
  - `docs/REVIEW_GUIDE.md` maps every README claim to the test, CI step or recorded run that
    proves it, and says where the proof is weak. It also lists the per-endpoint leakage a
    reviewer must accept and what the project does not claim.
  - `tests/test_review_guide.py` fails when a cited test, file, CI job or step does not exist, or
    when a "What Is Real" line has no row.
  - `docs/REVIEW_REQUEST_TEMPLATE.md` is the request to send to a third-party reviewer.
  - CI jobs now keep their JUnit counts, coverage and end-to-end JSON results. A new `evidence`
    job renders `docs/PORTFOLIO_EVIDENCE.md` from one run (`scripts/render_evidence.py`) and
    uploads it.
  - The release workflow refuses a tag when files other than that document changed since its
    evidence commit, checked by a test against the real workflow step.
  - New tests: the same keyword is stored as different tokens in two tenants; PS256 tokens
    verify; prod requires KMS once OIDC is configured. CI checks that PostgreSQL is not
    published by any Compose layering.
  - The CTO demo shows the audit export, `/metrics`, deletion and rotation, and lists the
    whole HTTP surface.
- Retrieval benchmarks with provenance (#50):
  - `encrypted_ir.tools.benchmark_retrieval` now times every ingest, then runs search OR, search
    AND, get-and-decrypt and RAG retrieve with warm-up rounds.
  - It reports n, mean, min, max and p50/p95/p99 ("n/a" below 20 or 100 samples).
  - It records the commit, the time, the CPU, the OS, Python, the SQLAlchemy driver and the
    database server, and writes JSON plus Markdown rendered from it. **Breaking:** `--report`,
    `--tenant-id` and `--auto-create` are replaced by `--output-dir`.
  - Reports for in-memory SQLite and the Compose PostgreSQL (100, 1,000 and 10,000 documents)
    are committed under `benchmarks/reports/<engine>/`.
  - New: `make bench-retrieval`, `make bench-retrieval-postgres` (`scripts/bench_postgres.sh`,
    which runs inside the image so PostgreSQL stays unpublished) and `benchmarks/README.md`.
  - `scripts/render_evidence.py` builds the PORTFOLIO_EVIDENCE benchmark table from the JSON, and
    a test fails if the table is out of date.
  - The master-only benchmarks job also runs the tool on SQLite and on PostgreSQL.
- The production auth path, end to end, without a cloud account (#48):
  - `docker-compose.oidc.yml` adds Keycloak 26, with a hand-written realm in
    `deploy/keycloak/`:
    - two tenants, a `tenant_id` attribute that only an administrator can edit;
    - client roles emitted as a top-level `roles` claim;
    - an audience mapper;
    - a confidential demo client (password grant, demo only).
  - The same file runs the API in `ENCRYPTED_IR_ENV=prod` on top of the KMS emulator, with no raw
    master key and no dev auth in its environment.
  - `scripts/oidc_smoke.sh` gets RS256 tokens for three users and checks their claims, then
    checks:
    - ingest and retrieval within a tenant;
    - 404 and empty results across tenants;
    - 403 for a read-only ingest;
    - 401 for a broken signature and for the dev API key;
    - the data and audit chain after a restart.
  - The CI `e2e` job runs it.
  - `docs/OIDC_DEPLOYMENT.md` covers the token rules, the local run, and claim mappings for
    Cognito, Auth0, Okta and Entra ID, taken from vendor documentation.
  - `ENCRYPTED_IR_TENANT_CLAIM` and `ENCRYPTED_IR_ROLES_CLAIM` are now in the README settings
    table.
- The AWS KMS path, end to end, without an AWS account (#49):
  - `docker-compose.kms.yml` adds moto server as a KMS emulator. LocalStack, which the roadmap
    named, needs an account auth token since its 2026.03.0 release.
  - `scripts/kms_smoke.sh`:
    - wraps a master key with `generate_kms_master_key` and starts the API with
      `ENCRYPTED_IR_KMS_PROVIDER=aws`;
    - ingests, restarts and retrieves;
    - checks the `_system` audit chain for one `key.unwrap` row per start;
    - checks that a key wrapped for `dev` fails to unwrap under `ENCRYPTED_IR_ENV=test`.
  - A new gating CI job, `e2e`, runs the script.
  - `docs/KMS_DEPLOYMENT.md` covers the production steps and CloudTrail. `docs/iam/` holds the
    IAM policies for the API role (`kms:Decrypt` only, with the encryption context required) and
    the operator role. `tests/test_kms_iam_policy.py` checks them against the code's context.
  - CI now checks relative Markdown links. Dependabot updates the Compose image digests.
- Tests (#46): a route matrix that fails when a `/v1` route lacks a 401, 403 or cross-tenant case;
  AES-SIV bit-flip, truncation and row-swap tamper tests; a test that pins token replay within its
  lifetime (documented in THREAT_MODEL as by design); the slow-JWKS test synchronizes with events
  instead of asserting wall-clock time.
- `python -m encrypted_ir.migrations upgrade|downgrade|current`, for running migrations without
  `alembic.ini` (#45). Dependabot also proposes Docker base-image updates.
- `encrypted_ir.rotation.rotate_tenant_keys`, `RotationReport`,
  `KeyManager.begin_rotation`, `KeyManager.stored_key_ids` and
  `StorageBackend.save_keys` (#42).
- `ENCRYPTED_IR_RATE_LIMITS` (JSON overrides of the per-operation and per-client limits),
  `ENCRYPTED_IR_RATE_LIMIT_MAX_KEYS` and `ENCRYPTED_IR_TRUSTED_PROXIES` (#47).
- Structured JSON logging is configured by `create_app` (#43): one access line per request with
  the route template, and `ENCRYPTED_IR_LOG_LEVEL`. Every line logged while handling a request
  carries its `X-Request-ID`.
- `ENCRYPTED_IR_METRICS_TOKEN` (#43).
- Docker `HEALTHCHECK` against `/health` (#43); the Compose CI job checks it reports healthy.

- Settings (#41): `ENCRYPTED_IR_DEV_API_KEY`, `ENCRYPTED_IR_DEV_TENANT_ID` and
  `ENCRYPTED_IR_JWT_SECRET` now live in `EncryptedIRSettings`, alongside the new
  `ENCRYPTED_IR_JWT_LEEWAY_SECONDS`, `ENCRYPTED_IR_OIDC_ALGORITHMS`,
  `ENCRYPTED_IR_JWKS_TIMEOUT_SECONDS`, `ENCRYPTED_IR_ENABLE_DOCS` and
  `ENCRYPTED_IR_MAX_BODY_BYTES`. The README lists them with their defaults.
- `/metrics` fields `unauthorized_count`, `forbidden_count`, `rate_limited_count` and
  `security_audit_dropped_count` (#41).
- `DELETE /v1/documents/{doc_id}` (#39). It deletes a document and its tokens in one transaction,
  needs the write or admin role, returns 204 or 404, and writes the audit event
  `document.delete`.
- Request limits on `POST /v1/documents` (#39): `doc_id` must match
  `^[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$` (so `/`, `.` and `..` are rejected); at most 256 explicit
  keywords of up to 128 characters; at most 32 metadata keys and 16 KB of metadata JSON. One
  document yields at most 10,000 extracted keywords.
- `KeyManager(audit_reads=True)` to persist access counts and audit every key read, plus
  `KeyManager.refresh()` and `KeyManager.get_or_create_active_key()`.
- `encrypted_ir.research`, a package for the unaudited prototypes (#37). Importing it issues an
  `encrypted_ir.errors.ResearchPrototypeWarning` (a `UserWarning`). Nothing in the core package or
  the API imports it, and its tests live in `tests/research/`.
- `CHANGELOG.md`.
- A release workflow (`.github/workflows/release.yml`). Pushing a `v*` tag checks that the tag
  matches the package version, builds the sdist and wheel, runs `twine check`, generates a
  CycloneDX SBOM, and publishes a GitHub Release whose notes are this file's section for that
  version.

## History before 0.9.0

No version was tagged or released before 0.9.0. Earlier work is in the git history and in
`docs/PORTFOLIO_EVIDENCE.md`.
