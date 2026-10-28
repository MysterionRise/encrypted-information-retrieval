# Review Request Template

Use this to ask a third party for a cryptographic or application-security review. No such review
has happened yet: until one does, the project claims no external audit ([REVIEW_GUIDE.md](REVIEW_GUIDE.md),
table 3). Copy the text below into the request, and fill in the bracketed parts.

---

**Subject:** Review request: encrypted-information-retrieval [version or commit]

**What it is.** A Python service (FastAPI, SQLAlchemy, PostgreSQL) that stores documents
encrypted with AES-GCM and retrieves them through tenant-scoped HMAC keyword tokens, for a RAG
pipeline. It has per-tenant keys wrapped under a KMS-unwrapped master key, OIDC authentication,
and a per-tenant HMAC audit chain. Code: [repository URL] at commit [SHA].

**In scope** (the durable path):
- `src/encrypted_ir/document_crypto.py`, `document_service.py`, `searchable.py`: document sealing
  and keyword tokens.
- `src/encrypted_ir/key_manager.py`, `storage_backend.py`, `master_key.py`, `kms_provider.py`,
  `rotation.py`: key wrapping, the KMS path and rotation.
- `src/encrypted_ir/audit.py` and `tools/export_audit.py`: the audit chain.
- `src/encrypted_ir/api/`: authentication, authorization, tenancy and error handling.

**Out of scope:**
- `src/encrypted_ir/research/` (prototypes, documented as unaudited);
- deployment infrastructure;
- the demo Keycloak realm.

**What we accept and what we ask you to check.** The leakage we accept is in
`docs/LEAKAGE_AND_ENDPOINTS.md` and `docs/THREAT_MODEL.md`: equality, query repetition, result
sizes and access patterns. Please check:
1. **Leakage.** Is there any leakage beyond the documented set?
2. **Bindings.** Are the bindings sound, so that a ciphertext, wrapped key or audit row cannot be
   moved between tenants, documents or purposes undetected?
3. **Isolation.** Can an authenticated caller reach another tenant's data or keys?
4. **Rotation.** Can a rotation that is interrupted or runs concurrently lose or expose data?
5. **Logs and errors.** Do logs, metrics, error bodies or audit rows leak plaintext, queries,
   tokens or key material?

**How to run it:** `docs/REVIEW_GUIDE.md` maps each claim to its test. `scripts/oidc_smoke.sh`
runs production mode locally with Keycloak and a KMS emulator. `docs/PORTFOLIO_EVIDENCE.md`
holds the CI evidence of the release.

**What we would like back:** findings with severity, reproduction steps and the commit reviewed.
We will publish a summary of the findings, with your agreement, and track each one as a GitHub
issue.
