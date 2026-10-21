# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). While the version is
below 1.0.0, minor versions may contain breaking changes.

The roadmap that drives these versions is in [docs/ROADMAP.md](docs/ROADMAP.md):
`0.9.0` closes Phase 0 (issue #26), `0.10.0` closes Phase 1 (issue #27), and
`1.0.0` closes Phase 2 (issue #28).

## [Unreleased]

### Removed

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
