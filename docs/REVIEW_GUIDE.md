# Review Guide

This guide is for reviewing the project in about thirty minutes. Each claim the README makes is
listed with the test, CI step or recorded run that backs it. The guide also lists the leakage you
are asked to accept, and what the project does not claim. `tests/test_review_guide.py` fails CI
if any proof below points at a test, file, CI job or step that does not exist, or if a "What Is
Real" line in the README has no row here.

**How to read the proofs**

- **A test ID**, such as `tests/test_api.py::TestHealthCheck::test_health_returns_200`, is a
  pytest test. All of `tests/` runs in three CI jobs:
  - `test`: Python 3.11 and 3.12, on PostgreSQL 16;
  - `coverage`: PostgreSQL 16, with the research extras;
  - `research`: with the research extras, on SQLite.

  Tests marked **[PG]** need PostgreSQL, so they run only in `test` and `coverage`.
- **A CI step**, such as CI `docker` "Ingest, restart, and retrieve", is a job and named step
  of `.github/workflows/ci.yml`. `ci-success` requires every gating job, including `docker`
  and `e2e`.
- **Evidence** links to [PORTFOLIO_EVIDENCE.md](PORTFOLIO_EVIDENCE.md), rendered from one CI run
  on the release commit.

A quick path through it:
1. Skim this page.
2. Run `./scripts/oidc_smoke.sh` (about two minutes with Docker): production mode, a real
   identity provider and a KMS emulator.
3. Open [LEAKAGE_AND_ENDPOINTS.md](LEAKAGE_AND_ENDPOINTS.md) and decide whether you accept
   table 2.

## 1. Claims and their proof

### "What Is Real" (README)

| README claim | Proof | Notes |
| --- | --- | --- |
| FastAPI service with health/readiness checks and versioned API routes. | `tests/test_api.py::TestHealthCheck::test_health_returns_200`, `tests/test_security_hardening.py::test_ready_endpoint_reports_ready_in_local_mode`, `tests/test_security_hardening.py::test_ready_endpoint_returns_503_when_not_ready`, `tests/test_api.py::TestOpenAPI::test_openapi_lists_exactly_the_durable_routes`; CI `docker` "Image HEALTHCHECK reports healthy" | The route list is pinned exactly. |
| Docker Compose stack with PostgreSQL persistence. | CI `docker` "Ingest, restart, and retrieve" (`scripts/compose_smoke.sh`); evidence: [end-to-end runs](PORTFOLIO_EVIDENCE.md#end-to-end-runs) | Proven by the script, not pytest. |
| Alembic migration for documents, keyword tokens, key metadata, and audit entries. | `tests/test_migrations_and_tools.py::test_migrated_schema_matches_models` (SQLite and [PG]), `tests/test_migrations_and_tools.py::test_alembic_upgrade_reaches_head`; CI `docker` "Migrations ran as a separate one-shot service" | The migrated schema must equal the models. |
| AES-GCM encrypted document storage for the durable API workflow. | `tests/test_document_crypto.py::test_wrong_context_is_rejected`, `tests/test_document_service.py::TestContextBinding::test_ciphertext_swapped_between_documents_is_rejected`, `tests/test_document_service.py::TestContextBinding::test_row_pointed_at_another_key_is_rejected`, `tests/test_api.py::TestIntegrityFailures::test_tampered_ciphertext_returns_generic_500_and_audits` | Ciphertexts are bound to tenant, document, purpose and key. |
| Tenant-scoped deterministic keyword tokens for retrieval. | `tests/test_document_service.py::TestTenantScopedTokens::test_same_keyword_is_stored_as_different_tokens_per_tenant`, `tests/test_api.py::TestTenantIsolation::test_search_does_not_return_other_tenant_documents`, `tests/test_route_matrix.py::TestEveryRoute::test_other_tenant_cannot_reach_tenant_a` | |
| Key lifecycle primitives, file/database storage backends, and AWS KMS abstraction. | `tests/test_key_manager.py::TestGetKeyForDecryption::test_retired_key`, `tests/test_key_manager.py::TestGetKeyForDecryption::test_destroyed_key_raises`, `tests/test_storage_backend.py::TestKeyManagerWithFileBackend::test_keys_persist_across_restarts`, `tests/test_storage_backend.py::TestDatabaseStorageBackend::test_key_manager_persists_with_database_backend`, `tests/test_kms_provider.py::TestEncryptionContext::test_context_sent_on_every_call`; CI `e2e` "KMS path (moto) - wrap, start, ingest, restart, retrieve, context binding" | The KMS path runs against moto server, an emulator, not AWS. |
| OIDC/JWKS production configuration path plus local demo auth for Compose. | `tests/test_auth.py::TestOIDCTokens::test_valid_token`, `tests/test_auth.py::TestOIDCTokens::test_ps256_tokens_verify_when_configured`, `tests/test_auth.py::TestOIDCTokens::test_only_configured_algorithms_are_accepted`, `tests/test_auth.py::TestSettingsValidation::test_dev_auth_requires_dev_environment`; CI `e2e` "Production mode (Keycloak + moto) - tenants, roles, 401/403/404, restart" | RS256, PS256 and ES256 are verified. The Keycloak run is production mode. |
| Audit records in a per-tenant HMAC chain, with an export tool that verifies it; they avoid plaintext, raw queries, tokens, and key material. | `tests/test_audit.py::TestAppend::test_tenants_have_separate_chains`, `tests/test_audit.py::TestVerify::test_row_copied_from_another_tenant`, `tests/test_audit.py::TestExportTool::test_exports_and_verifies`, `tests/test_audit.py::TestAppend::test_details_are_redacted`, `tests/test_security_hardening.py::test_document_operation_failures_write_sanitized_audit_rows` | "No tokens" is shown by the redaction tests, not by inspecting stored rows for real search tokens. |
| Benchmarks and evidence docs for local portfolio review. | `tests/test_migrations_and_tools.py::test_retrieval_benchmark_writes_json_and_markdown_with_provenance`, `tests/test_migrations_and_tools.py::test_portfolio_evidence_benchmark_table_matches_the_reports`, `tests/test_migrations_and_tools.py::test_render_evidence_ci_sections`; CI `evidence` "Render docs/PORTFOLIO_EVIDENCE.md" | The benchmark numbers come from the machine recorded in each report. The CI `benchmarks` job is informational. |

### Core versus research code

| README claim | Proof | Notes |
| --- | --- | --- |
| The `encrypted_ir` package exports only the durable path and the standard constructions. | `tests/research/test_research_package.py::test_research_classes_are_not_exported_from_the_top_level` | Checks that the research classes are absent, not the exact export list. |
| Importing `encrypted_ir.research` issues a `ResearchPrototypeWarning`. | `tests/research/test_research_package.py::test_importing_research_warns`, `tests/research/test_research_package.py::test_research_warning_is_a_user_warning` | |
| Nothing in the core package or the API imports it. | `tests/research/test_research_package.py::test_core_package_and_api_do_not_import_research` | A runtime check after importing the package and the app. It does not cover imports inside functions in `encrypted_ir.tools`. |

### Compose, image and configuration

| README claim | Proof | Notes |
| --- | --- | --- |
| A one-shot `migrate` service applies the migrations, then the API starts. | CI `docker` "Migrations ran as a separate one-shot service" | |
| PostgreSQL is reachable only from those two services. | CI `docker` "PostgreSQL is not published to the host" | Checked for the base file and the KMS and OIDC layers. |
| The image runs as a non-root user (uid 10001). | CI `docker` "The image runs as a non-root user" | |
| Dependencies come from the hash-pinned `requirements-docker.txt`. | `Dockerfile` (`pip wheel --require-hashes`); CI `docker` "Build and start the stack"; CI `security` "Audit dependencies for known vulnerabilities (pip-audit)" | The build fails on an unhashed line; no separate test. |
| The image includes boto3 for the AWS KMS path. | CI `docker` "The AWS KMS path starts from the image (boto3 is installed)"; CI `e2e` "KMS path (moto) - wrap, start, ingest, restart, retrieve, context binding" | |
| Compose refuses to start without the `.env` values. | CI `docker` "Compose refuses to start without the .env values" | |
| `/docs`, `/redoc` and `/openapi.json` return 404 unless `ENCRYPTED_IR_ENABLE_DOCS=true`. | `tests/test_api.py::TestOpenAPI::test_docs_are_off_by_default`, `tests/test_api.py::TestOpenAPI::test_docs_available` | |

### Authentication

| README claim | Proof | Notes |
| --- | --- | --- |
| Dev auth is off by default, refused unless `ENCRYPTED_IR_ENV=dev`, and needs a JWT secret of at least 32 bytes. | `tests/test_auth.py::TestSettingsValidation::test_dev_auth_is_off_by_default`, `tests/test_auth.py::TestSettingsValidation::test_dev_auth_requires_dev_environment`, `tests/test_auth.py::TestSettingsValidation::test_dev_auth_requires_a_32_byte_secret` | |
| Every token must carry `exp`, `iat`, a valid tenant claim and a non-empty roles claim; OIDC tokens also need `aud` and `iss`. | `tests/test_auth.py::TestDevTokens::test_rejected_claims_return_generic_401`, `tests/test_auth.py::TestOIDCTokens::test_rejected_claims`, `tests/test_auth.py::TestDevTokens::test_space_separated_roles_and_longest_tenant_are_accepted` | |
| Any role other than `read`, `write` and `admin` means 403. | `tests/test_auth.py::TestDevTokens::test_unknown_roles_return_403`, `tests/test_security_hardening.py::test_oidc_document_flow_rejects_missing_or_unknown_claims`, `tests/test_route_matrix.py::TestEveryRoute::test_insufficient_role_is_403` | |
| Production mode refuses a raw master key and dev auth, and requires OIDC and KMS. | `tests/test_security_hardening.py::test_settings_prod_rejects_dev_auth_and_raw_master_key`, `tests/test_security_hardening.py::test_settings_prod_requires_oidc_and_kms`, `tests/test_security_hardening.py::test_settings_prod_requires_kms_once_oidc_is_configured`; CI `e2e` "Production mode (Keycloak + moto) - tenants, roles, 401/403/404, restart" | |
| The production auth path runs locally with Keycloak, in `ENCRYPTED_IR_ENV=prod`. | `scripts/oidc_smoke.sh`, `tests/test_keycloak_realm.py::test_roles_claim_is_top_level_and_limited_to_the_api_client`; CI `e2e` "Production mode (Keycloak + moto) - tenants, roles, 401/403/404, restart"; evidence: [end-to-end runs](PORTFOLIO_EVIDENCE.md#end-to-end-runs) | It checks tenant-a and tenant-b isolation, 403 for a read-only ingest, 401 for a broken signature and for the dev API key, and the data after a restart. |
| Claim mappings for Cognito, Auth0, Okta and Entra ID. | `docs/OIDC_DEPLOYMENT.md` | From vendor documentation. **Not run** against those services. |

### Logs, rate limits and metrics

| README claim | Proof | Notes |
| --- | --- | --- |
| One JSON access line per request, with the route template, carrying `X-Request-ID` as `correlation_id`. | `tests/test_observability.py::TestRequestLogging::test_access_line_uses_the_route_template`, `tests/test_observability.py::TestRequestLogging::test_every_line_during_a_request_carries_its_request_id` | |
| Values that look like keys, card numbers or email addresses are redacted. | `tests/test_redaction.py::TestRedactText::test_base64_key_is_redacted`, `tests/test_redaction.py::TestRedactText::test_luhn_valid_card_is_redacted`, `tests/test_redaction.py::TestRedactText::test_ssn_and_email`, `tests/test_logging.py::TestStructuredFormatter::test_redacts_pii_in_message` | |
| Rate limits are in memory, per process, with the documented defaults. | `tests/test_rate_limiter.py::TestSettings::test_defaults_include_the_client_limit`, `tests/test_rate_limiter.py::TestBoundedState::test_bucket_count_is_capped`, `tests/test_rate_limiter.py::TestBoundedState::test_eviction_never_tightens_a_limit` | Only the client default (600 per minute) is asserted as a number. |
| The client limit covers every path except `/health`. | `tests/test_rate_limiter.py::TestClientLimit::test_ready_and_metrics_are_limited_but_health_is_not`, `tests/test_rate_limiter.py::TestClientLimit::test_unauthenticated_requests_are_limited` | |
| `/metrics` is Prometheus text keyed by route template, never a document ID. | `tests/test_api.py::TestMetrics::test_metrics_are_prometheus_text`, `tests/test_api.py::TestMetrics::test_metrics_count_requests_by_route_template`, `tests/test_observability.py::TestMetricLabels::test_exposition_never_contains_document_ids`; CI `docker` "Metrics expose route templates, never document IDs" | |
| `ENCRYPTED_IR_METRICS_TOKEN` protects `/metrics`. | `tests/test_observability.py::TestMetricsToken::test_token_required`, `tests/test_observability.py::TestMetricsToken::test_short_token_refused` | |

### Keys, rotation and audit export

| README claim | Proof | Notes |
| --- | --- | --- |
| `generate_kms_master_key` uses `GenerateDataKey` and prints only the wrapped key. | `tests/test_kms_provider.py::TestEncryptionContext::test_generate_tool_calls_generate_data_key_with_the_context`, `tests/test_kms_provider.py::TestEncryptionContext::test_generate_tool_wraps_with_the_environment_context` | |
| The encryption context binds the master key to its environment. | `tests/test_kms_provider.py::TestEncryptionContext::test_settings_provider_uses_environment_context`; CI `e2e` "KMS path (moto) - wrap, start, ingest, restart, retrieve, context binding" | The script shows a dev-wrapped key failing under `ENCRYPTED_IR_ENV=test`. |
| The IAM policies in `docs/iam/` require that context. | `tests/test_kms_iam_policy.py::test_api_runtime_role_can_only_decrypt_with_the_master_key_context`, `tests/test_kms_iam_policy.py::test_operator_role_wraps_with_the_context_and_describes_without_one`, `tests/test_kms_iam_policy.py::test_every_statement_allows_one_action_on_one_key_arn` | Checked against the code, not against AWS: moto does not enforce IAM. |
| The rotation tool re-encrypts and re-tokenizes, retires the old document key and destroys the old search key, with exit codes 0, 1, 2 and 3. | `tests/test_rotation.py::TestRotation::test_reencrypts_retokenizes_and_retires`, `tests/test_rotation.py::TestCli::test_complete_run`, `tests/test_rotation.py::TestCli::test_stop_and_resume`, `tests/test_rotation.py::TestCli::test_unreadable_document_exits_2`, `tests/test_rotation.py::TestInterruption::test_failed_batch_rolls_back_and_resume_finishes`, `tests/test_rotation.py::TestConcurrentWrites::test_concurrent_ingest_converges`, `tests/test_rotation.py::TestPostgres::test_a_write_holding_the_key_row_blocks_retirement` [PG] | |
| The master key rotates in AWS KMS. | none | Not tested: it is KMS-side behaviour (table 3). |
| `export_audit` verifies a chain, and `--check-head` detects dropped newest rows. | `tests/test_audit.py::TestExportTool::test_exports_and_verifies`, `tests/test_audit.py::TestExportTool::test_tampered_row_exits_2`, `tests/test_audit.py::TestExportTool::test_check_head_catches_a_rewritten_head` | |

### Security notes and test discipline

| README claim | Proof | Notes |
| --- | --- | --- |
| The ORE prototype's comparison needs no key, so ciphertext holders learn total order. | `tests/research/test_ore.py::TestORESecurityProperties::test_compare_requires_no_key`, `tests/research/test_ore.py::TestORESecurityProperties::test_right_component_leaks_block_differences` | A leakage the tests pin, not a guarantee. |
| Every `/v1` route is tested for 401, 403 and cross-tenant access. | `tests/test_route_matrix.py::test_every_durable_route_is_covered` | It fails when a new route lacks a case. |
| An unexpected 500 fails the test that caused it. | `tests/conftest.py` (`_fail_on_unexpected_500`) | A fixture, not a test of its own. |
| A release's evidence comes from its own code. | `tests/test_migrations_and_tools.py::test_release_guard_accepts_only_an_evidence_only_change`; `.github/workflows/release.yml` | The tag is refused if anything but PORTFOLIO_EVIDENCE changed since the evidence run. |

## 2. Leakage you are asked to accept

Full detail, with the mitigations, is in [LEAKAGE_AND_ENDPOINTS.md](LEAKAGE_AND_ENDPOINTS.md).

| Endpoint | What the server or an operator learns | Accept? |
| --- | --- | --- |
| `POST /v1/documents` | Document and metadata length, token count, ingest timing, the encrypting key's ID; deterministic tokens allow keyword frequency analysis within a tenant. | ☐ |
| `POST /v1/documents/search` | Query repetition, matching document IDs, result sizes and the access pattern. | ☐ |
| `GET /v1/documents/{doc_id}` | Which documents are read, and when. | ☐ |
| `DELETE /v1/documents/{doc_id}` | That a document ID existed (204 versus 404) for a caller of the same tenant. Deleted rows persist in database backups and WAL until they age out. | ☐ |
| `POST /v1/rag/retrieve` | Everything search leaks, plus plaintext released to the caller when `include_plaintext` is set (audited). | ☐ |
| `GET /health`, `GET /ready` | Package version and uptime; one pass/fail boolean per readiness check. | ☐ |
| `GET /metrics` | Request counts and latency by route template, rejection counts, and the number of tenants with cached keys, unless `ENCRYPTED_IR_METRICS_TOKEN` is set. | ☐ |
| Logs | Which tenants are active and when (document IDs, queries, plaintext and keys are not logged). | ☐ |

## 3. What the project does not claim

- **No external audit.** No cryptographic or application-security review by a third party has
  happened. A [review request template](REVIEW_REQUEST_TEMPLATE.md) is ready for one.
- **No zero-leakage retrieval.** There is no PIR, ORAM or TEE. Retrieval is deterministic keyword
  tokens, with the leakage in table 2.
- **No vector search, embeddings or model calls.** RAG support stops at retrieval.
- **Per-process limits and metrics.** Rate limits and metrics live in one process. Several
  replicas need an external limiter and metrics aggregation.
- **Unaudited research modules.** `encrypted_ir.research` (ORE, FF1, CKKS, post-quantum,
  differential privacy, forward-private SSE) is unaudited prototype code with known defects.
- **Emulators, not cloud services.** The KMS path runs against moto server, not AWS. moto does
  not enforce IAM, and KMS-side rotation of the master key is not exercised. The OIDC path runs
  against Keycloak, not a commercial identity provider, and the vendor claim mappings are
  documentation-derived.
- **Demo-only settings.** The Keycloak password grant and every committed secret are for the
  local demo only.
- **No deployment infrastructure.** There is no TLS termination, IaC, WAF, SIEM export, backup
  drill, SLO or log-retention setup.
- **Tamper evidence, not tamper proofing.** Whoever holds the master key can rewrite a tenant's
  audit chain consistently. Only exported head hashes kept elsewhere detect that.
