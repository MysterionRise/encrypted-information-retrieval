# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). While the version is
below 1.0.0, minor versions may contain breaking changes.

The roadmap that drives these versions is in [docs/ROADMAP.md](docs/ROADMAP.md):
`0.9.0` closes Phase 0 (issue #26), `0.10.0` closes Phase 1 (issue #27), and
`1.0.0` closes Phase 2 (issue #28).

## [Unreleased]

### Security

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
