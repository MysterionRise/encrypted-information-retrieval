# Security Policy

## Project security posture

This repository is a prototype for privacy-preserving retrieval in regulated AI/RAG systems. It
contains real cryptographic building blocks and an extensive test suite, but it is **not**
externally audited. Do not treat it as a production cryptography product without independent
review, operational hardening, and threat-specific validation.

The Docker Compose workflow is for local evaluation of encrypted document retrieval and the
RAG-ready API. Its demo authentication, demo master key and demo database password are
deliberately convenient defaults, not production controls.

## Supported versions

| Version | Supported | Notes |
| ------- | --------- | ----- |
| `master` | Yes | Fixes land here first. |
| `0.9.x` | Yes | First tagged release; see `CHANGELOG.md`. |
| Anything earlier | No | No earlier version was tagged or released. |

## Reporting a vulnerability

Please **do not** open a public issue, discussion or pull request for a suspected vulnerability.

Report it privately through GitHub:
**[Report a vulnerability](https://github.com/MysterionRise/encrypted-information-retrieval/security/advisories/new)**.
This uses GitHub's private vulnerability reporting, so only you and the maintainer can see it.

If that link returns 404, private reporting has not been enabled on the repository yet. In that
case, open a public issue titled "Security contact request" **without any details**. The
maintainer will reply with a private channel.

### What to include

- What is affected: module, endpoint, or workflow, plus version or commit.
- The impact you expect, for example cross-tenant data access, key exposure, or authentication
  bypass.
- Steps to reproduce, ideally a minimal script or test.
- Whether the issue is new leakage or contradicts what
  [`docs/LEAKAGE_AND_ENDPOINTS.md`](docs/LEAKAGE_AND_ENDPOINTS.md) says the system leaks.
- How you would like to be credited, if at all.

### What to expect

This is a single-maintainer project, so responses are best effort:

- **Acknowledgement:** within 7 days.
- **Assessment:** an assessment and a proposed fix or mitigation timeline, agreed with you.
- **Fix and disclosure:**
  - The fix is developed in a private fork attached to the advisory.
  - It is released, and then the GitHub Security Advisory is published, with credit if you want it.
  - For significant issues, a CVE is requested through GitHub.

## Scope

**In scope:**
- The durable API path: `/v1/documents*`, `/v1/rag/retrieve`, authentication, key management,
  storage, migrations and audit.
- The library modules under `src/encrypted_ir`, including the research modules. Those are
  unaudited prototypes, but reports about them are still welcome.
- The CI and release workflows.

**Out of scope:**
- Demo credentials in `docker-compose.yml`. They are documented demo values.
- Leakage that [`docs/LEAKAGE_AND_ENDPOINTS.md`](docs/LEAKAGE_AND_ENDPOINTS.md) already documents,
  unless the actual leakage is larger than documented.
- Vulnerabilities in third-party dependencies. Please report those upstream; `pip-audit` runs in
  CI to catch known ones.

## Known limitations

These are tracked publicly. They are not secrets, and you do not need to report them again.

| Area | Limitation | Tracking |
| ---- | ---------- | -------- |
| Retrieval leakage | Keyword tokens and blind indexes leak equality, query repetition, result sizes and access patterns by design. | [`docs/LEAKAGE_AND_ENDPOINTS.md`](docs/LEAKAGE_AND_ENDPOINTS.md) |
| ORE prototype | `ORE.compare()` needs no key, so anyone holding the ciphertexts learns their total order. Ciphertexts also leak partial plaintext bytes. It is not the Lewi-Wu construction its docstring names. | [#34](https://github.com/MysterionRise/encrypted-information-retrieval/issues/34), [#37](https://github.com/MysterionRise/encrypted-information-retrieval/issues/37) |
| OPE | Deprecated and decryptable without the key. Still used by the demo use cases. | [#37](https://github.com/MysterionRise/encrypted-information-retrieval/issues/37) |
| Research modules | FPE, CKKS, post-quantum, differential privacy and the forward/backward-private SSE classes are unaudited prototypes with known defects. | [#37](https://github.com/MysterionRise/encrypted-information-retrieval/issues/37), [#38](https://github.com/MysterionRise/encrypted-information-retrieval/issues/38) |
| Ciphertext binding | Document ciphertexts and wrapped tenant keys are not bound to their tenant, document or key ID through associated data. | [#40](https://github.com/MysterionRise/encrypted-information-retrieval/issues/40) |
| Authentication | Dev auth is on by default with a public HS256 secret outside production mode. JWT `exp` is not required. Error responses can include exception text. | [#41](https://github.com/MysterionRise/encrypted-information-retrieval/issues/41) |
| Key rotation | Rotation does not re-encrypt stored documents. | [#42](https://github.com/MysterionRise/encrypted-information-retrieval/issues/42) |
| Durable path | AND search breaks once a tenant has more than one search key. The per-tenant key cache does not reload across workers. | [#39](https://github.com/MysterionRise/encrypted-information-retrieval/issues/39) |
| Observability | `/metrics` is unauthenticated and keyed by raw request path, which can expose document IDs. | [#43](https://github.com/MysterionRise/encrypted-information-retrieval/issues/43) |
| Audit | Audit rows are ordinary database rows, not tamper-evident, and have no export. | [#44](https://github.com/MysterionRise/encrypted-information-retrieval/issues/44) |

The roadmap epics order this work: [#26](https://github.com/MysterionRise/encrypted-information-retrieval/issues/26) (Phase 0), [#27](https://github.com/MysterionRise/encrypted-information-retrieval/issues/27) (Phase 1) and [#28](https://github.com/MysterionRise/encrypted-information-retrieval/issues/28) (Phase 2).

## Security checks in this repository

**CI** (`.github/workflows/ci.yml`) runs on every push and pull request:
- **bandit** static analysis of `src/`.
- **ruff**, including the flake8-bandit `S` rules.
- **pip-audit** over `requirements.txt`, `requirements-api.txt` and `requirements-research.txt`.
  This step is blocking.
- The full test suite on Python 3.11 and 3.12, with a PostgreSQL service.
- A research job that runs the tests needing the optional TenSEAL and pqcrypto extras.
- A Docker Compose smoke test.

**Locally:**

```bash
make security            # bandit + pip-audit, same as CI
pre-commit install       # optional local hooks; CI does not run pre-commit
```

**Starting points for reviewers:**
- **Tenant isolation:**
  - `tests/test_blind_index.py::TestSecurityProperties::test_tenant_isolation`
  - `tests/test_api.py::TestDurableDocuments::test_document_tenant_isolation`
  - `tests/test_api.py::TestTenantIsolation::test_tenant_cannot_decrypt_other_tenant_data`
  - `tests/test_storage_backend.py::TestDatabaseStorageBackend::test_tenant_isolation`
- **Audit rows contain no plaintext, queries, tokens or key material:**
  - `tests/test_security_hardening.py::test_document_operations_write_sanitized_audit_rows`
  - `tests/test_security_hardening.py::test_document_operation_failures_write_sanitized_audit_rows`
- **Production settings validation:**
  - `tests/test_security_hardening.py::test_settings_prod_rejects_dev_auth_and_raw_master_key`
  - `tests/test_security_hardening.py::test_settings_prod_requires_oidc_and_kms`
- **Constant-time comparison:** `BlindIndexGenerator.verify_index` in `src/encrypted_ir/blind_index.py`
  uses `hmac.compare_digest`.

## External security audit

**Status: not completed.**

No external cryptographic review, penetration test or compliance audit has been performed. Before
any production use, engage an independent security firm for:
- a cryptographic review,
- an application penetration test,
- an assessment against the specific regulatory scope.

Any regulatory mapping in this repository is discussion material. It is not an audit result,
legal opinion or certification.

## Changes to this policy

| Date | Change |
| ---- | ------ |
| 2025-11-13 | Initial version. |
| 2026-07-07 | Repositioned as a prototype; clarified unaudited status. |
| 2026-10-20 | Rewrote the reporting process around GitHub private vulnerability reporting. Removed placeholder contacts and broken references. Added scope and a table of known limitations linked to their tracking issues. |
