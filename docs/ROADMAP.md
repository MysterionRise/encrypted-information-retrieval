# Roadmap

**Written:** October 20, 2026
**Tracker:** GitHub issues, grouped under three phase epics:
[#26 Phase 0](https://github.com/MysterionRise/encrypted-information-retrieval/issues/26),
[#27 Phase 1](https://github.com/MysterionRise/encrypted-information-retrieval/issues/27),
[#28 Phase 2](https://github.com/MysterionRise/encrypted-information-retrieval/issues/28).
**Supersedes:** `GITHUB_ISSUES.md` (retired), the roadmap bullets formerly in `README.md`, `CURRENT_STATUS.md` and `PORTFOLIO_CASE_STUDY.md`.

## Why this roadmap exists

The project is a working local prototype (FastAPI, PostgreSQL, AES-GCM document storage, tenant-scoped HMAC
keyword tokens) wrapped in a large research library and about seventeen documents. CI is green and 775 tests pass.
What holds credibility back is not missing features. It is the distance between what the repository *says* and
what it *does*:

- the GitHub tracker was empty while a twenty-issue backlog lived only in a markdown file, twelve Dependabot
  pull requests sat unmerged with green CI, and `version = "1.0.0"` with a "Beta" classifier had no tag or release;
- several cryptographic modules describe a stronger construction than they implement (see the findings appendix);
- the durable document path has real bugs that a reviewer would hit within minutes of rotating a key or running
  two workers;
- about half the docs are target-state text with ticked boxes for controls that do not exist, and `SECURITY.md`
  has placeholder contacts;
- CI gates that the docs call "required" are `continue-on-error`.

The goal chosen for the next phases is **portfolio credibility for CTO and security reviewers**: narrow the
product to the durable path, make every claim verifiable, fix the real bugs, and produce evidence a reviewer can
reproduce without a cloud account. Two further decisions follow from that goal: the research modules are kept but
quarantined under `encrypted_ir.research` with explicit prototype warnings, and the demo-only API routes that hold
random per-process keys are removed rather than made durable.

## Principle

A claim may live in this repository only if a test, a CI job, or a dated evidence run backs it. Everything else is
either labelled *target state* or archived.

## Phase 0: Truth and hygiene (epic #26, tag `v0.9.0`)

Docs, CI, metadata and docstrings only. No behavioural code change. Cheapest work, largest credibility gain.

| Issue | Title | Area |
| --- | --- | --- |
| [#29](https://github.com/MysterionRise/encrypted-information-retrieval/issues/29) | Merge the 12 open Dependabot PRs and align pre-commit pins with CI | ci |
| [#30](https://github.com/MysterionRise/encrypted-information-retrieval/issues/30) | Make CI gates real: coverage, benchmarks branch, research extras, security scan, permissions | ci |
| [#31](https://github.com/MysterionRise/encrypted-information-retrieval/issues/31) | Single-source the version, adopt honest semver, add CHANGELOG and a tag-triggered release workflow | ci, docs |
| [#32](https://github.com/MysterionRise/encrypted-information-retrieval/issues/32) | Fix SECURITY.md: real disclosure channel, no placeholders, no broken references | docs |
| [#33](https://github.com/MysterionRise/encrypted-information-retrieval/issues/33) | Consolidate docs: archive stale planning material, merge duplicates, fix claims that contradict the code | docs |
| [#34](https://github.com/MysterionRise/encrypted-information-retrieval/issues/34) | Correct overclaiming docstrings (ORE, SSE, HE, blind index) and add honest leakage tests | crypto, docs |
| [#35](https://github.com/MysterionRise/encrypted-information-retrieval/issues/35) | Repo meta and packaging hygiene: CONTRIBUTING, CODEOWNERS, templates, .gitignore, pyproject, lock file | ci, docs |

Exit: CI on `master` green with real gates; every doc current, labelled target-state, or archived; `SECURITY.md`
usable; `v0.9.0` tagged by the release workflow.

## Phase 1: Durable path correctness and honest scope (epic #27, tag `v0.10.0`)

| Issue | Title | Area |
| --- | --- | --- |
| [#36](https://github.com/MysterionRise/encrypted-information-retrieval/issues/36) | Remove the demo routes (`/v1/encrypt`, `/v1/decrypt`, `/v1/search/*`, `/v1/keys*`) and their process-global state | api |
| [#37](https://github.com/MysterionRise/encrypted-information-retrieval/issues/37) | Quarantine research modules under `encrypted_ir.research` with a prototype warning; delete OPE; fix blind-index KDF and multi-record bugs | crypto |
| [#38](https://github.com/MysterionRise/encrypted-information-retrieval/issues/38) | Fix the research modules' concrete defects and add official test vectors | crypto, tests |
| [#39](https://github.com/MysterionRise/encrypted-information-retrieval/issues/39) | DocumentService correctness: AND search across rotated keys, write-on-read, key cache, ingest race, keyword extraction, delete route | api |
| [#40](https://github.com/MysterionRise/encrypted-information-retrieval/issues/40) | Bind ciphertexts and wrapped keys to their context (versioned header, AES-GCM AAD, KMS EncryptionContext); encrypt or bound document metadata | crypto, kms |
| [#41](https://github.com/MysterionRise/encrypted-information-retrieval/issues/41) | Auth hardening: require `exp`, stop echoing exceptions, no public default secret, validate tenant claim, single settings source, non-blocking handlers | api |
| [#42](https://github.com/MysterionRise/encrypted-information-retrieval/issues/42) | Key rotation that actually re-encrypts documents (resumable tool), persisted KEK story, dead rotation code removed | kms |
| [#43](https://github.com/MysterionRise/encrypted-information-retrieval/issues/43) | Wire structured logging and Prometheus metrics for real; stop `/metrics` leaking doc IDs | ops |
| [#44](https://github.com/MysterionRise/encrypted-information-retrieval/issues/44) | One audit schema, tamper-evident hash chain, export tool, auth failures audited, dead audit sinks removed | ops, api |
| [#45](https://github.com/MysterionRise/encrypted-information-retrieval/issues/45) | Container and compose truthfulness: boto3 in the image, non-root, separate migrate step, no hard-coded secrets, CI smoke test | ops |
| [#46](https://github.com/MysterionRise/encrypted-information-retrieval/issues/46) | Test suite structure and adversarial coverage: conftest, negative auth tests, cross-tenant, tamper, Postgres-backed API suite, benchmarks out of the unit run | tests |
| [#47](https://github.com/MysterionRise/encrypted-information-retrieval/issues/47) | Rate limiter honesty: document single-process scope, evict buckets, make limits configurable, limit unauthenticated paths | api |

Suggested order: #36 and #37 first (they shrink the surface everything else has to cover), then #39, #40, #41
together (they touch the same code), then #42, #43, #44, #45, with #38, #46 and #47 in parallel.

Exit: API is `/v1/documents*`, `/v1/rag/retrieve`, `/health`, `/ready`, `/metrics`, each on the leakage map; research
modules warn on import and their tests run in CI; the full API suite passes on PostgreSQL in CI; a real rotation
tool is proven by a Postgres-backed test; `v0.10.0` tagged.

## Phase 2: Evidence and reviewed release (epic #28, tag `v1.0.0`)

| Issue | Title | Area |
| --- | --- | --- |
| [#48](https://github.com/MysterionRise/encrypted-information-retrieval/issues/48) | End-to-end OIDC evidence without a cloud account (Keycloak or dex in Compose, CI job in prod mode) | api, ops |
| [#49](https://github.com/MysterionRise/encrypted-information-retrieval/issues/49) | End-to-end KMS evidence without a cloud account (LocalStack KMS profile, prod-mode startup in CI, documented IAM policy) | kms, ops |
| [#50](https://github.com/MysterionRise/encrypted-information-retrieval/issues/50) | Benchmarks with provenance: percentiles, commit/date/hardware metadata, SQLite and Postgres, regenerate reports | tests |
| [#51](https://github.com/MysterionRise/encrypted-information-retrieval/issues/51) | Reviewer guide (claim to proof), refreshed evidence and demo script, cut `v1.0.0` | docs |

Exit: CI runs the API in `ENCRYPTED_IR_ENV=prod` against a local IdP and LocalStack KMS and the run is recorded in
`PORTFOLIO_EVIDENCE.md`; `REVIEW_GUIDE.md` maps every README claim to its proof; `v1.0.0` tagged.

## Not planned

These stay out of scope so that no document implies they exist. Each would be a new decision, not a continuation.

| Item | Why not now |
| --- | --- |
| Shared (Redis) rate limiting, multi-replica correctness beyond the key-cache fix | Portfolio evidence runs single-process; #47 documents the limit instead. |
| SIEM or immutable external audit sink | #44 gives a tamper-evident chain and an export tool, which is the honest local step. |
| IaC, TLS termination, WAF, SLO dashboards, runbooks | Deployment concerns for a pilot, not for a reviewable prototype. |
| Real Lewi-Wu ORE, client/server forward-private DSSE, true encrypted aggregates | Multi-week cryptography work that would still be unaudited; #34 and #38 make the current code honest instead. |
| PIR, ORAM, TEE/Nitro, vector retrieval, MPC | Listed in older docs as mitigations; they are research directions, not roadmap items. |
| External cryptographic or application-security audit | Only meaningful after Phase 2; a request-for-review template is part of #51. |

## How to verify progress

- Each issue has acceptance checkboxes; an issue is closed only when every box is ticked by a merged change.
- Each phase ends with a tag cut by the release workflow (#31) and a CHANGELOG entry.
- `docs/PORTFOLIO_EVIDENCE.md` is regenerated from a fresh run at the end of Phase 2; until then its date tells a
  reader how old the evidence is.

## Appendix: findings behind this roadmap

Line numbers refer to commit `d52d63d` (master on October 20, 2026). They will drift as the phases land; the
issues carry the same references.

### GitHub and process state

- 0 open issues; 4 closed issues from 2022 about an Elasticsearch parser that no longer exists.
- 12 open Dependabot PRs (#9, #10, #12, #13, #16, #17, #18, #19, #20, #21, #23, #24), all with green CI.
- No tags, no releases; `pyproject.toml:7` says `1.0.0`, `:17` says Beta.
- Last human commit July 8, 2026; the backlog in `docs/GITHUB_ISSUES.md` was never created as issues.

### Cryptographic claims versus code

- `src/encrypted_ir/ore.py:217-255`: `compare()` uses no key. An `ORE` instance with a different key sorts another
  key's ciphertexts correctly, so the ciphertext holder learns the full order (OPE-level leakage). `right_0` equals
  the top plaintext byte plus a per-key constant. The docstring (`:8-13, :36-42`) claims Lewi-Wu and "no global
  order leakage". `tests/test_ore.py:276-277` asserts nothing.
- `src/encrypted_ir/order_preserving.py:118-133`: `p = ct // (2^32 + 1)` recovers every plaintext without the key;
  identity function when `plaintext_bits == ciphertext_bits`; still the default in `use_cases.py:80, 373`.
- `src/encrypted_ir/searchable.py:342-692` (`ForwardPrivateSSE`): custom hash chain, not Sophos; `"strong"` mode
  auto-runs `re_encrypt()` (`:559-563`), which moves entries into a deterministic index (`:632-642`) and leaks more.
- `src/encrypted_ir/searchable.py:695-916` (`BackwardPrivateIndex`): deletes by plaintext `doc_id` (`:848-849`);
  the delete tokens (`:845`) are never used; no backward privacy; wrong citation (`:710`).
- `src/encrypted_ir/homomorphic.py:208-261`: `sum_vector`, `mean_vector`, `dot_product`, `weighted_sum` decrypt
  first. Not homomorphic.
- `src/encrypted_ir/fpe.py`: FF1 passes all 9 NIST SP 800-38G samples when run by hand; `tests/test_fpe.py`
  contains none of them.
- `src/encrypted_ir/blind_index.py:107`: KDF context is `f"{tenant_id}:{field_name}"` (ambiguous); `:319`
  `index_records` keeps one record per value.
- `src/encrypted_ir/post_quantum.py:536-543`: signature verified only if supplied. `differential_privacy.py:192-199`:
  `sensitivity=0` divides by zero; `:257-261` `register_tenant` resets the budget.

### Durable path bugs

- `src/encrypted_ir/document_service.py:202-241`: AND search needs `keywords x keys` matches once a tenant has more
  than one search key.
- `src/encrypted_ir/key_manager.py:378-381, 412-414` with `storage_backend.py:285-300`: every key read rewrites the
  key row (delete then insert) and inserts an audit row.
- `src/encrypted_ir/document_service.py:50-57`, `key_manager.py:295-301`: per-tenant `KeyManager` cached forever and
  loaded once; breaks with more than one worker.
- `src/encrypted_ir/searchable.py:124-127`: stop-word and length filters run before punctuation is stripped;
  `""` and `"the,"` get indexed. `:175-181`: ciphertext has no header and no associated data. `key_manager.py:260-265`:
  key wrapping has no associated data.
- `src/encrypted_ir/key_rotation.py:306-473`: no document re-encryption exists; `rotate_kek` never persists the
  re-wrapped master key (`:455`).
- `src/encrypted_ir/api/dependencies/auth.py:98-104, :168`: `exp` not required; `:16, :118-120`: public default HS256
  secret with dev auth on by default; `:109` and `routes/admin.py:92, 101`: exception text in responses.
- `src/encrypted_ir/api/routes/admin.py:123-139` with `main.py:86`: `/metrics` is unauthenticated JSON keyed by raw
  path, so it leaks `doc_id`s.
- `Dockerfile:14-15`: boto3 is not installed, so KMS mode cannot start from the image.

### CI and tests

- `.github/workflows/ci.yml:146`: coverage threshold `continue-on-error`; `:204`: benchmarks gated on `main` while the
  default branch is `master`; `:37` isort and `:190` safety non-blocking; research extras never installed, so 98 of
  775 tests always skip.
- `tests/test_benchmarks.py`: 80 tests, zero `assert`, runs in the unit suite.
- No `conftest.py`, no hypothesis, no official vectors, no expired-JWT or wrong-audience test, cross-tenant tests
  missing for RAG, search and keys, the one concurrency test cannot fail.

### Documentation

- Target-state controls shown as done: `docs/THREAT_MODEL.md:347-349, 404-426`, `docs/COMPLIANCE_NOTES.md:59, 68,
  90-91, 168, 190, 275, 316-330, 357, 363`, `docs/DECISIONS.md:364-366`, `docs/ARCHITECTURE.md:64, 293, 448`.
- `SECURITY.md:39, 42-43, 139, 165, 186, 211, 324, 327, 342, 360-361`: placeholders and broken references.
- Version literal duplicated in `pyproject.toml:7`, `src/encrypted_ir/__init__.py:54`, `api/main.py:34`,
  `api/routes/admin.py:73`, `Makefile:172`.
