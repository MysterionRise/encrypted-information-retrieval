# Threat Model

**Describes:** the code in this repository as of October 2026. It does not describe a target
architecture. Planned work is in [ROADMAP.md](ROADMAP.md), and the per-endpoint leakage table is
in [LEAKAGE_AND_ENDPOINTS.md](LEAKAGE_AND_ENDPOINTS.md).

**Status:** prototype, not externally audited. Every gap listed here has a public tracking issue.

## Assets

| Asset | Where it lives |
| --- | --- |
| Document plaintext | Only in memory during ingest and authorized retrieval |
| Per-tenant document encryption keys and search keys | `encrypted_ir_keys` table, wrapped under the app master key |
| App master key | Process memory. It is loaded from an environment variable (dev), or unwrapped once through AWS KMS at startup (production path). |
| Query keywords | Request bodies; never stored or audited in plaintext |
| Audit trail | `encrypted_ir_audit_log` table |

## Adversaries

| Adversary | What they can see | What protects the assets |
| --- | --- | --- |
| **A1. Database or backup reader** (honest-but-curious DBA, stolen backup, cloud storage operator) | Document ciphertexts, keyword tokens, plaintext `metadata_json`, wrapped tenant keys, audit rows, row counts and timestamps | AES-256-GCM on document bodies. Tenant keys are wrapped under a master key that is not stored in the database. Keyword tokens are HMACs under per-tenant keys. |
| **A2. Authenticated client of tenant A** | Its own tenant's documents and search results | Every query filters by the tenant from the authenticated identity. Cross-tenant tests exist for the document routes. |
| **A3. Operator with access to the API host** | The master key in memory, and therefore everything | Not mitigated in this repository. AWS KMS keeps the master key out of configuration at rest, not out of memory. |
| **A4. Network attacker** | Traffic, if TLS is not terminated in front of the API | Not provided. The repository ships no TLS termination; a deployment must add it. |
| **A5. Future quantum adversary** (harvest now, decrypt later) | Stored ciphertexts | Data at rest uses AES-256 and HMAC-SHA256, which are not broken by known quantum attacks at these sizes. JWT signatures (RS256) authenticate requests; they do not protect stored data. |

## The durable path: what protects what

This is the code behind `POST /v1/documents`, `POST /v1/documents/search`,
`GET /v1/documents/{doc_id}` and `POST /v1/rag/retrieve`.

| Data | Protection | Code |
| --- | --- | --- |
| Document content | AES-256-GCM with a random 96-bit nonce under a per-tenant key, in a versioned header that names the key. The associated data binds it to the tenant, the document ID and its purpose, so a swapped or edited ciphertext fails to decrypt ([#40], ADR-007). Rows written before that format stay readable without the binding. | `src/encrypted_ir/document_crypto.py`, `DocumentService` |
| Keyword index | `HMAC-SHA256(per-tenant search key, lowercased keyword)`, one row per keyword per document. Deterministic. | `search_token` in `src/encrypted_ir/searchable.py`, `DocumentService` |
| Document metadata | Sealed like the content, with its own purpose label so content and metadata cannot be swapped ([#40]). Legacy rows keep plaintext `metadata_json`. | `encrypted_ir_documents.encrypted_metadata` |
| Tenant keys | AES-GCM wrapped under the app master key, bound by associated data to the tenant, key ID, key type and version, so a wrapped key copied to another tenant or relabelled does not unwrap ([#40]). Rotated by `rotate_tenant_keys`, which re-encrypts and re-tokenizes every document, then retires the old document key and destroys the old search key (ADR-018, [#42]). | `src/encrypted_ir/key_manager.py`, `src/encrypted_ir/rotation.py` |
| App master key | Environment variable, or AWS KMS `Decrypt` at startup with an encryption context (application, environment, purpose) and a pinned key ID. The KMS path runs end to end in CI against moto server, a KMS emulator (`scripts/kms_smoke.sh`), including a key wrapped for one environment failing to unwrap in another. It has not run against AWS itself, and the IAM policies are not exercised ([#49]). | `src/encrypted_ir/master_key.py`, `src/encrypted_ir/kms_provider.py` |
| Authentication | Production mode requires OIDC: tokens verified against a JWKS, with RS256, PS256 or ES256 only, and `exp`, `iat`, `aud` and `iss` required. Every token needs a tenant claim matching `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$` (so not `_system`) and a non-empty roles claim. A dev API key and dev HS256 JWTs exist for local demos; they are off by default, refused unless `ENCRYPTED_IR_ENV=dev`, and need a secret of at least 32 bytes. Failures return a generic 401 ([#41]). | `src/encrypted_ir/api/dependencies/auth.py`, `src/encrypted_ir/settings.py` |
| Audit | One entry schema in a per-tenant HMAC chain keyed from the master key (ADR-017), with a head row per tenant. Plaintext, queries, tokens and key material are redacted before writing. Ingest, delete and key changes commit together with their audit row; a read whose audit row fails returns 500. `python -m encrypted_ir.tools.export_audit` exports and verifies a chain ([#44]). | `src/encrypted_ir/audit.py`, `DocumentService`, `DatabaseStorageBackend` |
| Rate limiting | In memory and per process, so it is not shared across workers or replicas ([#47]). Each tenant has a limit per operation, checked after authentication; every request except `/health` also counts against a per-client-address limit, checked before authentication. Client addresses come from `X-Forwarded-For` only when the peer is in `ENCRYPTED_IR_TRUSTED_PROXIES`. State is bounded: refilled buckets are dropped and each operation keeps at most `ENCRYPTED_IR_RATE_LIMIT_MAX_KEYS` buckets. | `src/encrypted_ir/api/dependencies/rate_limiter.py`, `src/encrypted_ir/api/request_context.py` |

### Leakage on the durable path

Leakage to A1, the database reader:

- **Keyword equality and frequency within a tenant.** The same keyword produces the same token in
  every document of a tenant, so token counts mirror keyword frequencies.
- **Document and metadata length**, approximately, from ciphertext length.
- **Which key encrypted each document**, from the key ID in the row and in the ciphertext header.
- **Metadata of legacy rows**, written before [#40], which stays plaintext until the rotation tool
  re-encrypts the row.

Leakage to anyone who observes queries (A1 with query logs, or a host operator):

- **Query repetition**, because a repeated query produces the same tokens.
- **Result sets and sizes, and the access pattern**, because matching document IDs are visible.

With auxiliary knowledge of the corpus, these leakages enable known leakage-abuse attacks on
keyword search (Islam, Kuzu and Kantarcioglu 2012; Cash, Grubbs, Perry and Ristenpart 2015).
The design accepts that trade-off for a prototype and documents it per endpoint in
[LEAKAGE_AND_ENDPOINTS.md](LEAKAGE_AND_ENDPOINTS.md).

## Library and research primitives

None of these are used by the durable path or reachable through the API; the demo routes that
exposed some of them were removed in [#36]. AES-SIV and the blind index are standard constructions in
the core package. The rest are unaudited prototypes in `encrypted_ir.research`, which issues a
`ResearchPrototypeWarning` on import ([#37]). The OPE module was deleted because it was decryptable
without the key.

| Primitive | Construction | Leakage and known issues | Tracking |
| --- | --- | --- | --- |
| Deterministic encryption (`deterministic.py`) | AES-SIV (RFC 5297) from `cryptography` | Equality of plaintexts under the same key. Callers pass no associated data. | [#38] |
| Blind index (`blind_index.py`) | HMAC-SHA256 truncated to 128 bits by default (8 to 32 bytes allowed), per-tenant and per-field keys derived from a length-prefixed context | Equality within tenant and field. About 2^64 collision resistance at the default length. | [#38] (golden vectors) |
| ORE (`research/ore.py`) | CLWW-style prefix ORE over 32-bit integers, **not** Lewi-Wu | `compare()` needs no key, so whoever holds the ciphertexts learns their **total order**, the same as OPE. Also leaks plaintext byte differences, the most significant byte given one known pair, and equality. `encrypt_float` truncates instead of rounding. | [#34], [#38] |
| Forward-private SSE (`research/forward_private_sse.py`, `ForwardPrivateSSE`) | Custom hash chain, not Sophos | `"strong"` mode moves entries into a deterministic index, which leaks keyword co-occurrence for keywords never searched. State cannot be persisted. | [#38] |
| "Backward-private" index (`research/forward_private_sse.py`, `BackwardPrivateIndex`) | Token-set index keyed by `doc_id` | Provides **no** backward privacy. Deletes are fully visible, and the returned delete tokens are unused. | [#38] |
| FF1 format-preserving encryption (`research/fpe.py`) | NIST SP 800-38G FF1 | Passes the nine NIST sample vectors when run by hand; the vectors are not in the test suite yet. Helpers default to an empty tweak. | [#38] |
| CKKS (`research/homomorphic.py`) | TenSEAL, N=8192 | The aggregate helpers decrypt and finish in plaintext. The secret key can be exported in the clear. | [#38] |
| ML-KEM, ML-DSA and hybrid KEM (`research/post_quantum.py`) | pqcrypto 0.4 bindings, plus a custom `SHA256(kem_ss ‖ x25519_ss)` combiner | The combiner is not X-Wing and binds no public keys. Signature checking is skipped when no signature is passed. Needs pqcrypto below 1.0. | [#38] |
| Differential privacy (`research/differential_privacy.py`) | Textbook Laplace, Gaussian and exponential mechanisms | Uses floating-point noise (Mironov 2012). The classical Gaussian bound is not checked for ε < 1. The budget can be reset by re-registering a tenant. | [#38] |

## Residual risks

| Risk | Effect | Tracking |
| --- | --- | --- |
| Concurrent first ingest in two processes | Two processes ingesting for a new tenant at the same moment can each create a key. Both keys stay valid and every process converges on the newest one, so this costs an extra key, not correctness. | [#39] (documented) |
| Rotation is operator-run, and some legacy rows keep an old search key | A compromised key stays in use until someone runs the rotation tool. Documents ingested with explicit keywords before ADR-018 keep their old search key (still searchable, reported by the tool) until they are ingested again. Retired document keys are kept, so a backup taken before the rotation stays decryptable by whoever holds the master key. | [#42] (documented) |
| Rejected-request audit is rate-bounded | Beyond 20 rows per minute per tenant or client address, or 120 per process, 401, 403 and 429 responses are counted in `/metrics` but not audited one by one. | [#41], [#44] (documented) |
| Token replay within its lifetime | Bearer tokens are stateless: the API checks signature, issuer, audience, `iat` and `exp`, but keeps no record of tokens it has seen, so a captured token works for anyone until it expires. This is by design for stateless JWTs; keep lifetimes short at the identity provider and use TLS. | (documented; `tests/test_auth.py::TestDevTokens::test_replay_of_a_valid_token_is_accepted_until_it_expires`) |
| OIDC not validated against a live identity provider | Verification is tested with a fake JWKS; issuer-specific claim shapes may differ. | [#48] |
| `/metrics` open by default | Anyone who can reach the port sees per-route request volumes and the number of cached tenants (no document IDs). Set `ENCRYPTED_IR_METRICS_TOKEN` or restrict the port. | [#43] (documented) |
| Audit chain trusts the master key | Anyone holding the app master key (the API process, or an operator running the export) can rewrite a tenant's chain consistently. A database writer without the key can drop the newest rows and rewrite the head row to match. Exported head hashes, kept where database writers cannot change them and checked with `--check-head`, detect both. Failure and rejection audits are best effort. | [#44] (documented) |

## Explicitly not provided

This repository has no PIR, ORAM, trusted execution environment, HSM integration, TLS
termination, immutable or external audit sink, or external security review. Older documents
listed some of these as mitigations; those documents are in [archive/](archive/README.md). The
roadmap's "Not planned" section explains why each is out of scope for now.

## References

- Cash, Grubbs, Perry and Ristenpart, "Leakage-Abuse Attacks Against Searchable Encryption", CCS 2015.
- Islam, Kuzu and Kantarcioglu, "Access Pattern Disclosure on Searchable Encryption", NDSS 2012.
- Naveed, Kamara and Wright, "Inference Attacks on Property-Preserving Encrypted Databases", CCS 2015.
- Chenette, Lewi, Weis and Wu, "Practical Order-Revealing Encryption with Limited Leakage", FSE 2016.
- Lewi and Wu, "Order-Revealing Encryption: New Constructions, Applications, and Lower Bounds", CCS 2016.
- Bost, "Sophos: Forward Secure Searchable Encryption", CCS 2016.
- Bost, Minaud and Ohrimenko, "Forward and Backward Private Searchable Encryption from Constrained Cryptographic Primitives", CCS 2017.
- Mironov, "On Significance of the Least Significant Bits for Differential Privacy", CCS 2012.
- RFC 5297 (AES-SIV); NIST SP 800-38G (FF1); FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA).

[#34]: https://github.com/MysterionRise/encrypted-information-retrieval/issues/34
[#36]: https://github.com/MysterionRise/encrypted-information-retrieval/issues/36
[#37]: https://github.com/MysterionRise/encrypted-information-retrieval/issues/37
[#38]: https://github.com/MysterionRise/encrypted-information-retrieval/issues/38
[#39]: https://github.com/MysterionRise/encrypted-information-retrieval/issues/39
[#40]: https://github.com/MysterionRise/encrypted-information-retrieval/issues/40
[#41]: https://github.com/MysterionRise/encrypted-information-retrieval/issues/41
[#42]: https://github.com/MysterionRise/encrypted-information-retrieval/issues/42
[#43]: https://github.com/MysterionRise/encrypted-information-retrieval/issues/43
[#44]: https://github.com/MysterionRise/encrypted-information-retrieval/issues/44
[#47]: https://github.com/MysterionRise/encrypted-information-retrieval/issues/47
[#48]: https://github.com/MysterionRise/encrypted-information-retrieval/issues/48
[#49]: https://github.com/MysterionRise/encrypted-information-retrieval/issues/49
