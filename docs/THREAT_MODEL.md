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
| Document content | AES-256-GCM with a random 96-bit nonce under a per-tenant key. No associated data binds the ciphertext to its tenant or document ([#40]). | `SearchableEncryption.encrypt_document` in `src/encrypted_ir/searchable.py` |
| Keyword index | `HMAC-SHA256(per-tenant search key, lowercased keyword)`, one row per keyword per document. Deterministic. | `SearchableEncryption`, `DocumentService` |
| Document metadata | Stored as plaintext JSON ([#40]). | `encrypted_ir_documents.metadata_json` |
| Tenant keys | AES-GCM wrapped under the app master key, with no associated data ([#40]). | `src/encrypted_ir/key_manager.py` |
| App master key | Environment variable, or AWS KMS `Decrypt` at startup. The KMS path is tested with mocks only; live validation is [#49]. | `src/encrypted_ir/master_key.py`, `src/encrypted_ir/kms_provider.py` |
| Authentication | Production mode requires OIDC with RS256 tokens verified against a JWKS. Outside production, a dev API key and dev HS256 JWTs with a public default secret are enabled by default ([#41]). | `src/encrypted_ir/api/dependencies/auth.py`, `src/encrypted_ir/settings.py` |
| Audit | Database rows. Plaintext, queries, tokens and key material are dropped before writing. The rows are not tamper-evident and cannot be exported ([#44]). | `DocumentService.record_audit_event` |
| Rate limiting | In-memory and per process, so it is not shared across workers or replicas ([#47]). | `src/encrypted_ir/api/dependencies/rate_limiter.py` |

### Leakage on the durable path

Leakage to A1, the database reader:

- **Keyword equality and frequency within a tenant.** The same keyword produces the same token in
  every document of a tenant, so token counts mirror keyword frequencies.
- **Document length**, approximately, from ciphertext length.
- **Metadata**, in full, because it is plaintext.

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
| Ciphertexts and wrapped keys are not bound to their context | A database writer can swap ciphertexts between rows or tenants without detection. | [#40] |
| Concurrent first ingest in two processes | Two processes ingesting for a new tenant at the same moment can each create a key. Both keys stay valid and every process converges on the newest one, so this costs an extra key, not correctness. | [#39] (documented) |
| Rotation does not re-encrypt documents | Retiring a compromised key leaves its documents under that key. | [#42] |
| JWT `exp` not required; exception text in error bodies | Tokens without an expiry never expire. Internals leak in 401 responses and `/ready`. | [#41] |
| `/metrics` unauthenticated and keyed by raw path | Document IDs are visible to anyone who can reach the endpoint. | [#43] |
| Audit rows not tamper-evident | A database writer can alter or remove audit history. | [#44] |
| Docker image lacks boto3 | The KMS production path cannot start from the shipped image. | [#45] |

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
[#45]: https://github.com/MysterionRise/encrypted-information-retrieval/issues/45
[#47]: https://github.com/MysterionRise/encrypted-information-retrieval/issues/47
[#49]: https://github.com/MysterionRise/encrypted-information-retrieval/issues/49
