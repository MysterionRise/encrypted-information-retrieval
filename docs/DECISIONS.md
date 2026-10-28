# Architecture Decision Records (ADR)

> **How to read this file (October 2026).**
>
> - ADR-001 to ADR-010 were written in 2025 as target architecture. Their **Status** lines were
>   corrected in October 2026 to say what is actually implemented.
> - Their "Compliance Mapping" entries are targets, not certifications.
> - Latency and throughput figures inside those ADRs are design-time estimates, not measurements.
>   Measured numbers are in `benchmarks/reports/`.
> - ADR-011 to ADR-016 record decisions that are already reflected in the code, or accepted for
>   the roadmap.
>
> Current state is described in `docs/ARCHITECTURE.md` (As built) and `docs/THREAT_MODEL.md`.

**Project**: Encrypted Information Retrieval for Financial Services
**Last Updated**: October 2026

## Table of Contents

- [ADR-001: Use AES-SIV for Deterministic Encryption](#adr-001-use-aes-siv-for-deterministic-encryption)
- [ADR-002: Implement Blind Indexes for Equality Search](#adr-002-implement-blind-indexes-for-equality-search)
- [ADR-003: Adopt DSSE with Forward Privacy](#adr-003-adopt-dsse-with-forward-privacy)
- [ADR-004: Migrate from OPE to ORE for Range Queries](#adr-004-migrate-from-ope-to-ore-for-range-queries)
- [ADR-005: Use CKKS/BFV Homomorphic Encryption](#adr-005-use-ckks-bfv-homomorphic-encryption)
- [ADR-006: Envelope Encryption with KMS](#adr-006-envelope-encryption-with-kms)
- [ADR-007: Crypto-Agile Design with Algorithm Identifiers](#adr-007-crypto-agile-design-with-algorithm-identifiers)
- [ADR-008: Optional PIR Mode for Zero-Leakage Queries](#adr-008-optional-pir-mode-for-zero-leakage-queries)
- [ADR-009: TEE Integration for Sensitive Operations](#adr-009-tee-integration-for-sensitive-operations)
- [ADR-010: Post-Quantum Cryptography Roadmap](#adr-010-post-quantum-cryptography-roadmap)
- [ADR-011: FastAPI, PostgreSQL and Alembic for the Durable Service](#adr-011-fastapi-postgresql-and-alembic-for-the-durable-service)
- [ADR-012: AES-GCM Documents with HMAC Keyword Tokens on the Durable Path](#adr-012-aes-gcm-documents-with-hmac-keyword-tokens-on-the-durable-path)
- [ADR-013: OIDC/JWKS in Production, Explicit Dev Auth Otherwise](#adr-013-oidcjwks-in-production-explicit-dev-auth-otherwise)
- [ADR-014: One KMS-Wrapped App Master Key, Locally Wrapped Tenant Keys](#adr-014-one-kms-wrapped-app-master-key-locally-wrapped-tenant-keys)
- [ADR-015: Quarantine Research Modules](#adr-015-quarantine-research-modules)
- [ADR-016: Remove the Demo-Only API Routes](#adr-016-remove-the-demo-only-api-routes)

---

## ADR-001: Use AES-SIV for Deterministic Encryption

**Date**: 2025-01-11
**Status**: Accepted. Implemented in `deterministic.py` as a library primitive. The durable document path uses AES-GCM plus HMAC keyword tokens instead (ADR-012).
**Decision Makers**: Security Architecture Team

### Context

We need deterministic encryption for equality searches on account numbers, customer IDs, and SSNs. Traditional approaches include:
1. **AES-GCM with fixed nonce**: Catastrophic failure if nonce reused
2. **AES-ECB**: No authentication, weak security
3. **AES-SIV**: Misuse-resistant AEAD
4. **AES-GCM-SIV**: Misuse-resistant AEAD (RFC 8452)

### Decision

**Use AES-SIV (RFC 5297) for deterministic encryption.**

### Rationale

**Pros**:
- ✅ **Misuse-resistant**: Nonce reuse safe (critical for deterministic mode)
- ✅ **Authenticated**: Built-in MAC prevents tampering
- ✅ **Standards-based**: RFC 5297, well-analyzed
- ✅ **Available in `cryptography`**: Stable Python library support
- ✅ **512-bit keys**: AES-256-SIV provides strong security

**Cons**:
- ⚠️ **Deterministic leakage**: Equality patterns visible (acceptable trade-off for use case)
- ⚠️ **Slightly slower**: ~20% overhead vs. AES-GCM (published estimate; not measured here)

**Alternatives Considered**:
- **AES-GCM with fixed nonce**: Rejected (catastrophic if nonce reused accidentally)
- **AES-GCM-SIV**: Acceptable alternative; AES-SIV chosen for maturity
- **Format-Preserving Encryption (FF1)**: Use only where format constraints exist (e.g., legacy systems requiring specific field widths)

### Consequences

- **Security**: Strong confidentiality and authenticity; controlled equality leakage documented in THREAT_MODEL.md
- **Performance**: not measured for this ADR. Measured retrieval numbers, with provenance, are in `benchmarks/reports/`.
- **Leakage Mitigation**: Complement with blind indexes (ADR-002) for reduced leakage

### Compliance Mapping

- Target: **PCI DSS 3.5.1**: AES-256 encryption
- Target: **GDPR Art. 32**: State-of-the-art encryption
- Target: **NYDFS § 500.15**: Encryption at rest

### References

- [RFC 5297: Synthetic Initialization Vector (SIV)](https://datatracker.ietf.org/doc/html/rfc5297)
- [cryptography library](https://cryptography.io/en/latest/hazmat/primitives/aead/)

---

## ADR-002: Implement Blind Indexes for Equality Search

**Date**: 2025-01-11
**Status**: Accepted. Implemented in `blind_index.py` as a library primitive. Not used by the durable document path. The ambiguous key-derivation context and the one-record-per-value bug were fixed in [#37].
**Decision Makers**: Security Architecture Team

### Context

Direct deterministic encryption (AES-SIV) reveals equality patterns globally. We need a technique to:
1. Enable equality searches
2. Reduce leakage compared to pure deterministic encryption
3. Scope equality leakage per tenant

### Decision

**Implement HMAC-SHA256 blind indexes with per-tenant salts.**

### Rationale

**Pros**:
- ✅ **Scoped leakage**: Equality visible only within tenant, not globally
- ✅ **Collision-resistant**: about 2^64 (birthday bound) for the 128-bit truncated output
- ✅ **Standards-based**: HMAC-SHA256 (FIPS 198-1)
- ✅ **Simple implementation**: No complex crypto; integrates with existing HMAC primitives
- ✅ **CipherSweet pattern**: Proven approach used in production systems

**Cons**:
- ⚠️ **Still leaks equality**: Within tenant scope
- ⚠️ **No ciphertext recovery**: Index alone doesn't decrypt; need separate ciphertext storage

**Alternatives Considered**:
- **Pure deterministic encryption**: Rejected (leaks equality globally)
- **Searchable encryption (SSE)**: Over-engineered for simple equality; use for full-text search (ADR-003)
- **Order-Revealing Encryption**: Leaks more than needed (order unnecessary for equality)

### Implementation

```python
# Blind index generation
def create_blind_index(value: str, tenant_id: str, field_type: str) -> str:
    # Normalize input
    normalized = normalize_unicode(value.lower())

    # Get tenant-specific salt from KMS
    salt = get_tenant_salt(tenant_id, field_type)

    # Compute HMAC
    index = hmac.new(salt, normalized.encode('utf-8'), hashlib.sha256)

    return base64.b64encode(index.digest()[:16]).decode('ascii')  # 128-bit index
```

### Consequences

- **Security**: Equality leakage scoped to tenant; frequency analysis limited to tenant dataset
- **Performance**: not measured on its own. Token computation is part of the per-document ingest time in `benchmarks/reports/`.
- **Storage**: Index stored alongside encrypted ciphertext
- **Rotation**: Index keys rotate with DEKs (90-day cycle)

### Compliance Mapping

- Target: **GDPR Art. 25**: Pseudonymization
- Target: **GDPR Art. 32**: Data minimization

### References

- [CipherSweet Blind Indexing](https://ciphersweet.paragonie.com/internals/blind-index)
- [NIST FIPS 198-1: HMAC](https://csrc.nist.gov/publications/detail/fips/198/1/final)

---

## ADR-003: Adopt DSSE with Forward Privacy

**Date**: 2025-01-11
**Status**: Partially implemented. `ForwardPrivateSSE` is a custom hash-chain prototype, not Sophos. Its "strong" mode leaks more than "balanced". It is not used by the durable path, which uses deterministic HMAC tokens (ADR-012). See [#38].
**Decision Makers**: Security Architecture Team

### Context

Searchable Symmetric Encryption (SSE) enables keyword search on encrypted documents but leaks information. We need to:
1. Enable keyword search on encrypted documents/emails
2. Minimize leakage (especially update leakage)
3. Provide clear security guarantees

### Decision

**Implement Dynamic SSE (DSSE) with forward privacy; provide optional PIR mode for zero-leakage.**

### Rationale

**Pros**:
- ✅ **Forward privacy**: New document additions unlinkable to past queries
- ✅ **Replay protection**: Nonce-based freshness
- ✅ **Practical performance**: the design-time figure was never measured. Measured search latency at 10,000 documents is in `benchmarks/reports/`.
- ✅ **Well-studied**: Σoφoς-style constructions analyzed in literature

**Cons**:
- ⚠️ **Access pattern leakage**: Which documents match a query
- ⚠️ **Search pattern leakage**: Query repetition visible
- ⚠️ **No backward privacy** (MVP): Deletes leak (roadmapped for P1)

**Alternatives Considered**:
- **Static SSE**: Rejected (no forward privacy; vulnerable to LEAP-style attacks)
- **ORAM**: Rejected (100-1000x overhead (published estimate; not measured here); impractical for FS latency requirements)
- **PIR only**: Use as optional mode; too slow for default

### Leakage Profile

**Leaked Information**:
- Query repetition (query ID linkage)
- Access patterns (which documents match)
- Result sizes (number of matches)
- Update patterns (timing, frequency)

**Not Leaked**:
- Query keywords (without auxiliary data)
- Document content
- Forward linkage (new docs ↛ past queries)

### Consequences

- **Security**: Documented leakage; acceptable for non-PII documents; use PIR mode for sensitive collections
- **Performance**: not measured. Measured retrieval numbers are in `benchmarks/reports/`.
- **Operational**: Monitor for scraping attempts; rate-limit queries

### Compliance Mapping

- Target: **GDPR Art. 32(1)(a)**: Pseudonymization
- ⚠️ **Requires**: Clear user disclosure of leakage profile

### References

- [Σoφoς (Sophos): Forward Secure SSE](https://eprint.iacr.org/2016/728)
- [Cash et al., "Leakage-Abuse Attacks", CCS 2015](https://eprint.iacr.org/2015/946)

---

## ADR-004: Migrate from OPE to ORE for Range Queries

**Date**: 2025-01-11
**Status**: Not achieved as written. `encrypted_ir.research.ore` implements a CLWW-style prefix ORE, not Lewi-Wu. Its comparison needs no key, so its order leakage equals OPE's ([#34]). The OPE module and the use cases built on it were deleted in [#37].
**Decision Makers**: Security Architecture Team

### Context

**Current**: Simplified Order-Preserving Encryption (OPE) using PRF-based linear mapping.

**Problem**: Classical OPE leaks full plaintext distribution, enabling inference attacks. Recent research (Naveed et al., 2015; Grubbs et al., 2017) demonstrates practical plaintext recovery.

### Decision

**Migrate to Order-Revealing Encryption (ORE) or structured encryption (bucketed B-tree).**

### Rationale

**ORE (Lewi-Wu) Pros**:
- ✅ **Reduced leakage**: Leaks only order, not distribution shape
- ✅ **Standards-track**: Well-analyzed construction
- ✅ **Comparison without decryption**: Server can compare encrypted values

**ORE Cons**:
- ⚠️ **Still leaks order**: Adversary learns sorting
- ⚠️ **Complex implementation**: Requires careful coding

**Structured Encryption Alternative**:
- Use bucketed B-tree with padding + client-side post-filtering
- **Pros**: Leaks only bucket access (coarser than individual order)
- **Cons**: Client-side filtering overhead

**Alternatives Considered**:
- **Keep OPE**: Rejected (unacceptable leakage for financial amounts)
- **TEE-only**: Use as optional mode; need fallback for non-TEE environments
- **No range queries**: Rejected (essential for FS use cases)

### Implementation Plan

1. **Phase 1 (P0)**: Implement Lewi-Wu ORE comparator
2. **Phase 2 (P1)**: Add structured encryption option (bucketed B-tree)
3. **Phase 3 (P1)**: Add TEE-assisted range evaluation (AWS Nitro Enclaves)

### Consequences

- **Security**: Order leakage acceptable for dates/timestamps; avoid for amounts if possible
- **Performance**: not measured. The ORE prototype's micro-benchmarks are in `benchmarks/test_research.py`.
- **Migration**: Lazy re-encryption on read; complete migration in 90 days

### Compliance Mapping

- Target: **Risk mitigation**: Reduces inference attack surface
- ⚠️ **Requires**: Updated DPIA for residual order leakage

### References

- [Lewi & Wu, "Order-Revealing Encryption", 2016](https://eprint.iacr.org/2016/612)
- [Naveed et al., "Inference Attacks on Property-Preserving Encrypted Databases", CCS 2015](https://dl.acm.org/doi/10.1145/2810103.2813651)

---

## ADR-005: Use CKKS/BFV Homomorphic Encryption

**Date**: 2025-01-11
**Status**: Accepted, CKKS only. BFV is not implemented. The research module's aggregate helpers decrypt before summing ([#38]).
**Decision Makers**: Security Architecture Team

### Context

We need encrypted computation for credit scoring and analytics. Options:
1. **Secure Multi-Party Computation (SMPC)**: Requires multiple parties
2. **Trusted Execution Environments (TEE)**: Hardware dependency
3. **Fully Homomorphic Encryption (FHE)**: Single-party, no trusted hardware

### Decision

**Use CKKS (approximate arithmetic) and BFV (exact integers) via TenSEAL (Microsoft SEAL wrapper).**

### Rationale

**Pros**:
- ✅ **IND-CPA security**: Semantic security under RLWE/LWE
- ✅ **SIMD batching**: Efficient parallel operations
- ✅ **Python support**: TenSEAL provides high-level API
- ✅ **Production-ready**: Microsoft SEAL used in real-world deployments

**Cons**:
- ⚠️ **Performance**: 100-1000x slower than plaintext (published estimate; not measured here)
- ⚠️ **Ciphertext size**: 100KB+ per encrypted vector
- ⚠️ **Complexity**: Requires crypto expertise for parameter tuning

**Alternatives Considered**:
- **OpenFHE**: Acceptable alternative; TenSEAL chosen for Python integration
- **Concrete (Zama)**: Promising but newer; reevaluate in 2026
- **TEE-only**: Use as complementary option; FHE provides no-trust-anchor alternative

### Use Cases

1. **Credit Scoring**: CKKS for logistic regression on encrypted features
2. **Risk Analytics**: BFV for exact integer computations
3. **Encrypted ML Inference**: CKKS for neural network layers

### Consequences

- **Performance**: 2-5s per credit score computation (acceptable for batch processing)
- **Scalability**: GPU acceleration planned for P1 (10-100x speedup)
- **Operational**: Require parameter tuning per use case; document in runbooks

### Compliance Mapping

- Target: **GDPR Art. 25**: Privacy by design
- Target: **NYDFS § 500.15**: Encryption of nonpublic info

### References

- [Microsoft SEAL](https://github.com/microsoft/SEAL)
- [TenSEAL Documentation](https://github.com/OpenMined/TenSEAL)

---

## ADR-006: Envelope Encryption with KMS

**Date**: 2025-01-11
**Status**: Partially implemented.
- A single app master key is unwrapped through AWS KMS at startup (`master_key.py`; run end to end in CI against the moto KMS emulator, not against AWS), and per-tenant keys are wrapped locally under it.
- The master key is created by KMS `GenerateDataKey` and rotated by KMS-side rotation of the customer master key.
- Tenant keys are rotated by an operator tool, not on a schedule (ADR-018).
- No HSM, CloudHSM or CloudTrail integration exists in this repository.
**Decision Makers**: Security Architecture Team

### Context

Key management complexity is a top operational challenge (59% of IT professionals report significant impact). We need:
1. Centralized key management
2. FIPS 140-3 Level 3 HSM backing
3. Audit trail of all key operations
4. Rotation without service disruption

### Decision

**Implement envelope encryption with KEKs in AWS KMS/CloudHSM.**

### Rationale

**Pros**:
- ✅ **KEK never leaves HSM**: Keys protected by hardware
- ✅ **FIPS 140-3 Level 3**: Compliance-ready
- ✅ **Audit logging**: CloudTrail records KMS calls, if the operator configures a trail; nothing in this repository does (see [KMS_DEPLOYMENT.md](KMS_DEPLOYMENT.md))
- ✅ **Per-tenant isolation**: Separate DEKs per tenant
- ✅ **Rotation**: Re-wrap DEKs without KEK change

**Cons**:
- ⚠️ **Cloud dependency**: Requires AWS/Azure/GCP KMS
- ⚠️ **Cost**: ~$1/month per CMK + API call charges
- ⚠️ **Latency**: a KMS call costs a network round trip. The built system calls KMS once, at startup (ADR-014); that call was not timed.

**Alternatives Considered**:
- **Local HSM (Thales Luna)**: For on-premises deployments
- **Vault (HashiCorp)**: For hybrid cloud; KMS preferred for pure cloud
- **Self-managed keys**: Rejected (operational complexity, audit challenges)

### Implementation

```
┌─────────────────────────────────────┐
│ Key Hierarchy                       │
│                                     │
│  CMK (Customer Master Key)          │
│  └─ in AWS KMS HSM                  │
│     └─ FIPS 140-3 Level 3           │
│                                     │
│  DEK1 (Data Encryption Key)         │
│  └─ Encrypted by CMK                │
│  └─ Tenant A                        │
│                                     │
│  DEK2 (Data Encryption Key)         │
│  └─ Encrypted by CMK                │
│  └─ Tenant B                        │
└─────────────────────────────────────┘
```

### Consequences

- **Security**: KEK isolation, HSM-backed, audit trail
- **Performance**: no DEK cache with a TTL was built. The API unwraps the master key once at startup and keeps tenant keys in memory (ADR-014); single-document decrypt times are in `benchmarks/reports/`.
- **Operational**: Automated rotation; 90-day DEK rotation, annual KEK rotation

### Compliance Mapping

- Target: **PCI DSS 3.6.1**: Protect cryptographic keys
- Target: **NIST SP 800-57**: Key management best practices
- Target: **DORA Art. 9**: ICT risk management

### References

- [AWS KMS Best Practices](https://docs.aws.amazon.com/kms/latest/developerguide/best-practices.html)
- [NIST SP 800-57 Part 1 Rev. 5](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)

---

## ADR-007: Crypto-Agile Design with Algorithm Identifiers

**Date**: 2025-01-11 (revised 2026-10-21)
**Status**: Accepted and implemented for stored documents ([#40]). The 2025 draft below the line
proposed a fixed 16-byte key ID and several algorithm IDs; what shipped is narrower and is described
first.
**Decision Makers**: Security Architecture Team

### As implemented

Document content and document metadata are sealed by `encrypted_ir.document_crypto`:

```
version (u8 = 1) || algorithm (u8 = 1, AES-256-GCM) || key_id_len (u8, 1..255) || key_id (UTF-8)
|| nonce (12 bytes) || ciphertext || tag (16 bytes)

AES-GCM associated data = header || lp("encrypted-ir/document/v1") || lp(purpose)
                          || lp(tenant_id) || lp(doc_id)          lp = 4-byte big-endian length prefix
purpose = "content" | "metadata" | "keywords"
```

- The row's `algorithm` column is `aes-256-gcm/v1` for this format. Rows written before it keep
  `aes-gcm` (`iv || tag || ciphertext`, no associated data) and stay readable; the rotation tool
  (ADR-018, [#42]) re-encrypts them into this format. Changing a new row's `algorithm` to `aes-gcm` cannot downgrade it,
  because the legacy path then fails the GCM tag check.
- Decryption checks that the header's version, algorithm and key ID match the row, and that the
  associated data matches the tenant, document and purpose. Swapping ciphertexts between rows,
  tenants or purposes, editing the header, or pointing the row at another key all fail.
- Tenant keys are wrapped under the app master key with associated data
  `lp("encrypted-ir/tenant-key/v1") || lp(tenant_id) || lp(key_id) || lp(key_type) || lp(version)`
  and `wrap_format: 1` in their metadata. Keys without `wrap_format` were wrapped with no associated
  data; they still unwrap and are re-wrapped the next time they are saved.
- The app master key is wrapped by AWS KMS with the encryption context `application`,
  `environment` and `purpose` (`app-master-key`).
- The header reveals the key ID and format version to anyone who can read the row; both were
  already visible in the row's columns.

### Original 2025 design (not implemented as written)

### Context

Cryptographic algorithms have finite lifespans. We must prepare for:
1. **Algorithm breaks**: Unexpected cryptanalysis
2. **Post-quantum migration**: NIST FIPS 203/204/205 (2024)
3. **Compliance changes**: Future regulatory requirements

### Decision

**Design for crypto-agility: include algorithm identifiers in ciphertext headers; support versioned keys.**

### Alternatives Considered

- **Fixed algorithms**: Rejected (requires full data re-encryption for algorithm changes)
- **External mapping**: Rejected (lose self-describing property)

### Consequences

- **Migration**: Decrypt with the old format, re-encrypt with the new one (the rotation tool, ADR-018).
- **Backward compatibility**: Old ciphertexts remain readable until they are re-encrypted.

### References

- [NIST IR 8413: Status Report on the Third Round of the NIST PQC Standardization Process](https://csrc.nist.gov/publications/detail/nistir/8413/final)

---

## ADR-008: Optional PIR Mode for Zero-Leakage Queries

**Date**: 2025-01-11
**Status**: Not planned. See the roadmap's "Not planned" section.
**Decision Makers**: Security Architecture Team

### Context

SSE leaks access patterns. For high-sensitivity collections (e.g., sanctions lists, PEPs), we need zero-leakage query capability.

### Decision

**Provide feature-flag PIR mode using SimplePIR/DoublePIR for selected collections.**

### Rationale

**Pros**:
- ✅ **Zero server-side leakage**: Server learns nothing about queries
- ✅ **Recent advances**: 2023-2024 PIR schemes practical for 10k-100k records
- ✅ **Opt-in**: Use only for sensitive collections (performance vs. privacy trade-off)

**Cons**:
- ⚠️ **Performance**: 10-100x slower than SSE (published estimate; not measured here)
- ⚠️ **Database size limit**: Practical for <1M records
- ⚠️ **Implementation complexity**: Requires specialized library (SealPIR, SimplePIR)

**Alternatives Considered**:
- **ORAM**: Rejected (1000x+ overhead (published estimate; not measured here))
- **TEE-only**: Complementary; PIR provides no-trust-anchor alternative

### Implementation Plan

1. **Phase 1 (P1)**: Integrate SimplePIR for single-server PIR
2. **Phase 2 (P2)**: Add DoublePIR for improved throughput
3. **Use Cases**: Sanctions screening, PEP lists, watchlists

### Consequences

- **Performance**: no PIR mode was built, so nothing was measured. Published PIR schemes cost far more per query than keyword-token search.
- **Scalability**: not measured (no PIR mode exists).
- **Operational**: Enable via feature flag; document trade-offs clearly

### References

- [SimplePIR](https://eprint.iacr.org/2022/949)
- [DoublePIR](https://eprint.iacr.org/2023/1087)

---

## ADR-009: TEE Integration for Sensitive Operations

**Date**: 2025-01-11
**Status**: Not planned. See the roadmap's "Not planned" section.
**Decision Makers**: Security Architecture Team

### Context

Some operations require plaintext processing (e.g., complex predicates, ML inference). We need a trusted execution environment to:
1. Decrypt ciphertexts server-side
2. Process in isolated, attested environment
3. Return encrypted results

### Decision

**Integrate AWS Nitro Enclaves for sensitive server-side decryption.**

### Rationale

**Pros**:
- ✅ **Hardware isolation**: Separate CPU, memory from host
- ✅ **Attestation**: Cryptographic proof of code integrity
- ✅ **KMS integration**: Attested key release (KMS policy: decrypt only inside enclave)
- ✅ **Regulatory acceptance**: Recognized by auditors for data processing

**Cons**:
- ⚠️ **AWS-specific**: Vendor lock-in (Azure Confidential VMs, GCP Confidential Computing as alternatives)
- ⚠️ **Performance**: ~10% overhead vs. non-enclave (published estimate; not measured here)
- ⚠️ **Operational complexity**: Attestation flow, enclave management

**Alternatives Considered**:
- **Intel SGX**: Rejected (side-channel vulnerabilities; Spectre/Meltdown mitigations incomplete)
- **AMD SEV**: Azure Confidential VMs (acceptable alternative)
- **Software-only**: Rejected (no hardware isolation)

### Use Cases

1. **Range query decryption**: Decrypt ORE ciphertexts inside enclave for filtering
2. **ML inference**: Decrypt features, run model, re-encrypt scores
3. **Complex predicates**: SQL-like operations on plaintext (inside enclave)

### Consequences

- **Security**: Zero server-side leakage (outside enclave); rely on enclave integrity
- **Performance**: 10% overhead (published estimate; not measured here); acceptable for high-sensitivity operations
- **Operational**: Require attestation flow; document in runbooks

### References

- [AWS Nitro Enclaves](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html)
- [Azure Confidential Computing](https://azure.microsoft.com/en-us/solutions/confidential-compute/)

---

## ADR-010: Post-Quantum Cryptography Roadmap

**Date**: 2025-01-11
**Status**: Research module only. ML-KEM, ML-DSA and a hybrid KEM exist in `encrypted_ir.research.post_quantum` (pqcrypto 0.4) and are not used by the durable path. The hybrid combiner is not X-Wing ([#38]).
**Decision Makers**: Security Architecture Team

### Context

NIST finalized PQC standards (FIPS 203/204/205) in August 2024. Large-scale quantum computers pose "harvest now, decrypt later" threat to long-lived data.

### Decision

**Implement hybrid PQC by 2025 H2; full migration by 2026 H2.**

### Rationale

**Pros**:
- ✅ **Risk mitigation**: Protect against future quantum adversaries
- ✅ **Hybrid approach**: Combine classical + PQC (security against both classical and quantum)
- ✅ **Standards-based**: NIST-approved algorithms (Kyber, Dilithium, Falcon)

**Cons**:
- ⚠️ **Performance**: PQC key operations ~2-10x slower (published estimate; not measured here)
- ⚠️ **Key/signature sizes**: Kyber public key ~1.6KB (vs. 32 bytes for X25519)
- ⚠️ **Implementation maturity**: Libraries stabilizing (liboqs, PQClean)

### Migration Plan

**Phase 1 (2025 H2)**: Hybrid Key Establishment
- TLS 1.3 with Kyber768 + X25519
- KMS key derivation: Kyber-encapsulated key ⊕ ECDH shared secret

**Phase 2 (2026 Q2)**: Hybrid Signatures
- Dilithium3 + ECDSA P-384 for audit logs, certificates

**Phase 3 (2026 H2)**: Full PQC Migration
- Retire classical-only algorithms
- Kyber-only mode for new keys

### Consequences

- **Performance**: 5-10% overhead (hybrid mode) (published estimate; not measured here)
- **Storage**: ~2KB per key (vs. 32 bytes classical)
- **Compliance**: Meet PQC migration mandates (expected 2026-2028)

### References

- [NIST FIPS 203: Kyber (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204: Dilithium (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205: SLH-DSA (SPHINCS+)](https://csrc.nist.gov/pubs/fips/205/final)

---

## ADR-011: FastAPI, PostgreSQL and Alembic for the Durable Service

**Date**: 2026-07-06 (recorded 2026-10-20)
**Status**: Accepted. Implemented.

### Context

The 2025 library had no service, no persistence and no migrations, so nothing survived a restart and
nothing could be demonstrated end to end.

### Decision

Expose the durable document and RAG workflow through FastAPI. Persist documents, keyword tokens, wrapped
keys and audit rows in PostgreSQL through SQLAlchemy Core. Manage the schema with Alembic. SQLite remains
supported for tests and local runs.

### Consequences

- Docker Compose runs PostgreSQL plus the API. The persistence smoke test in `docs/CTO_DEMO_SCRIPT.md`
  exercises it.
- The per-tenant key cache reloads from the database, so several workers can share one database
  ([#39]). The rate limiter is in memory and per process by design ([#47]).

---

## ADR-012: AES-GCM Documents with HMAC Keyword Tokens on the Durable Path

**Date**: 2026-07-06 (recorded 2026-10-20)
**Status**: Accepted. Implemented in `DocumentService`, with the sealed format of ADR-007.

### Context

ADR-001 (AES-SIV), ADR-003 (forward-private DSSE) and ADR-004 (ORE) describe primitives that exist as
library or research code. The durable path needed one construction that is standard, testable and simple
to reason about.

### Decision

Encrypt document bodies and their metadata with AES-256-GCM under a per-tenant key, bound to the
tenant and document (ADR-007). Index them with deterministic `HMAC-SHA256(per-tenant search key,
keyword)` tokens stored one row per keyword per document.

### Consequences

- The leakage is explicit and documented per endpoint: keyword equality and frequency within a tenant,
  query repetition, result sizes and access patterns.
- No forward or backward privacy.
- Ciphertexts and wrapped keys are bound to their tenant, document and key ([#40]). Metadata is
  encrypted, so search results decrypt it per match.

---

## ADR-013: OIDC/JWKS in Production, Explicit Dev Auth Otherwise

**Date**: 2026-07-06 (recorded 2026-10-20)
**Status**: Accepted. Implemented, and hardened in [#41]. Runs end to end in CI against Keycloak with the API in `prod` (`scripts/oidc_smoke.sh`, [#48]).

### Decision

- **Production mode** (`ENCRYPTED_IR_ENV=prod`):
  - Requires OIDC issuer, audience and JWKS URL.
  - Verifies bearer tokens against the JWKS with an allowlist of asymmetric algorithms
    (`RS256` by default; `PS256` and `ES256` may be enabled; `HS*` and `none` are refused at
    startup).
  - Requires `exp`, `iat`, `aud` and `iss`, with a configurable leeway (30 s by default).
  - Takes the tenant and roles from configurable claims. The tenant must match
    `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`; the roles claim is required and must name known roles.
  - Rejects dev auth.
- **Dev mode only** (`ENCRYPTED_IR_ENV=dev`): an explicit dev API key and dev HS256 tokens exist so
  the local demo needs no identity provider. Both are off by default. Dev tokens need a secret of
  at least 32 bytes and the same claims as OIDC tokens except `aud` and `iss`.
- All configuration comes from validated settings at startup, and every failure returns the same
  401 body.

### Consequences

- The local demo works without cloud accounts, but must opt in to dev auth (Compose does).
- A token can no longer live forever, impersonate the reserved `_system` tenant, or get a role
  it does not name.
- Clients cannot tell an expired token from a forged one; operators read the reason in the
  audit log.

---

## ADR-014: One KMS-Wrapped App Master Key, Locally Wrapped Tenant Keys

**Date**: 2026-07-06 (recorded 2026-10-20)
**Status**: Accepted. Implemented. The KMS path runs end to end in CI against the moto KMS emulator (`scripts/kms_smoke.sh`, [#49]); it has not run against AWS.

### Decision

One application master key per deployment. Production mode unwraps it once at startup with AWS KMS
`Decrypt`; dev reads it from an environment variable. Per-tenant document and search keys are generated
locally and stored AES-GCM-wrapped under that master key.

### Consequences

- One KMS call per process start instead of one per request.
- The master key stays in process memory, so a host compromise exposes every tenant (THREAT_MODEL A3).
- Tenant keys are rotated, and documents re-encrypted, by `rotate_tenant_keys` (ADR-018). The master
  key is rotated in KMS: automatic rotation of the customer master key keeps the old key material to
  decrypt the existing wrapped master key, so it needs no re-wrapping. The library's earlier `rotate_kek`,
  which never persisted the re-wrapped key, is removed.

---

## ADR-015: Quarantine Research Modules

**Date**: 2026-10-20
**Status**: Accepted and implemented ([#37]).

### Context

ORE, OPE, FF1, CKKS, post-quantum, differential privacy and the forward/backward-private SSE classes are
exported next to the durable-path code. Several of them describe stronger guarantees than they provide.

### Decision

- Move them under `encrypted_ir.research`, which emits a prototype warning on import.
- Delete OPE.
- Keep only standard, tested constructions in the core package.
- Run the research tests in CI with the optional extras installed.

---

## ADR-016: Remove the Demo-Only API Routes

**Date**: 2026-10-20
**Status**: Accepted and implemented ([#36]).

### Context

`/v1/encrypt`, `/v1/decrypt`, `/v1/search/*` and `/v1/keys*` hold random per-process keys in module
globals. They do not survive a restart and share nothing with the durable path.

### Decision

Remove these routes rather than make them durable. Library-level demos of blind indexes and ORE stay in
`examples/portfolio_demo.py`.

### Consequences

The API surface and the leakage map then describe only durable, tested code.

---

## ADR-017: One Audit Schema in a Per-Tenant HMAC Chain

**Date**: 2026-10-28
**Status**: Accepted and implemented ([#44]).

### Context

Audit entries had two shapes (API events and key events), five sinks (the database table, an in-memory
deque on `KeyManager`, `audit.jsonl` from the file backend, an `AuditLogger` that wrote to the log, and
the storage-backend API), no export, and nothing to show that a row had not been edited or deleted.
Success rows were written after the operation, in a separate transaction.

### Decision

- One entry schema (version 1) for every row, with `details` redacted by the logging policy.
- One sink: `encrypted_ir_audit_log`. Each tenant's rows form a chain:
  `entry_hash = HMAC-SHA256(audit_key, prev_hash || canonical_json(entry))`, with `prev_hash` of the first
  row all zeros. `audit_key` is HKDF-SHA256 of the app master key with the tenant ID in `info`.
- `encrypted_ir_audit_chain_heads` keeps each tenant's last `seq` and hash. An append updates that row
  first, which locks it until the transaction ends, so appends for one tenant are serialized on both
  PostgreSQL and SQLite without retries.
- Writes that change state (ingest, delete, key changes) append in their own transaction, so the
  operation and its audit row commit together. Reads append before the response and fail the request
  if they cannot. Failure and rejection audits are best effort.
- `python -m encrypted_ir.tools.export_audit` writes a tenant's chain as JSON lines, verifies it from the
  first row and prints the head; `--check-head` checks a head from an earlier export.

### Rationale

**Pros**:
- Editing, deleting, reordering or moving rows between tenants breaks verification.
- No extra secret to manage: the key follows the master key, including KMS unwrapping.
- The head row catches a truncated tail and is the serialization point.

**Cons**:
- Anyone holding the master key can rebuild a consistent chain. The API process holds it, and so does
  whoever runs the export; both can already decrypt every document.
- A database writer can drop the newest rows and rewrite the head row to match.
- Appends for one tenant are serialized, which bounds that tenant's write throughput.

**Alternatives considered**:
- Plain SHA-256 chain: anyone with database write access could rebuild it.
- A separate audit signing key: another secret to provision and rotate, with no gain while the API
  process holds both keys.
- An external append-only sink (WORM storage, SIEM): out of scope for this repository; exported heads
  are the local step toward it (see the roadmap's "Not planned" list).

### Consequences

Migration 0004 adds the chain columns and the heads table; rows written before it keep NULL chain
columns, are not verified and are counted separately by the export tool. `KeyManager.get_audit_log`,
`AuditLogger` and the file backend's audit file are removed. Operators should store exported head
hashes where database writers cannot change them.

---

## ADR-018: Tenant Key Rotation Re-encrypts Documents; the Master Key Rotates in KMS

**Date**: 2026-10-28
**Status**: Accepted and implemented ([#42]).

### Context

Rotating a key created a new version but left every stored document and search token under the old
key, so retiring a compromised key was not possible. There were three rotation paths that did not
connect: `KeyManager.rotate_key`, `KeyRotationManager` (re-encryption by callback, with nothing calling
it), and `rotate_kek`, whose re-wrapped master key was never persisted. Search tokens are HMACs of the
keywords, which the database did not store, so tokens could not be rebuilt under a new key.

### Decision

- **Keyword list.** Ingest seals each document's sorted keyword list with the document key
  (purpose `keywords`, ADR-007), so rotation can rebuild its tokens.
- **One rotation path:** `encrypted_ir.rotation.rotate_tenant_keys`, run as
  `python -m encrypted_ir.tools.rotate_tenant_keys`.
  - **Start.** A row in `encrypted_ir_key_rotations` claims the tenant. Then
    `KeyManager.begin_rotation` creates the successor keys and marks the old ones ROTATING, in one
    transaction.
  - **Re-encrypt.** Documents move to the successors in `doc_id` order, one transaction per batch.
    Each row is written back with a compare-and-swap on its ciphertext, with one audit event per
    batch. Passes repeat until one makes no progress.
  - **Finish.** Old keys that nothing references are retired: the document key becomes RETIRED and
    is kept, and the search key becomes DESTROYED and its bytes are cleared. The key row is locked
    before the references are counted.
  - **Interruptions.** A run that stops for any reason leaves every document readable and
    searchable, and `--resume` continues it.
- **Concurrent writes.** Ingest locks its two key rows `FOR SHARE` and accepts only ACTIVE or
  ROTATING keys. If the rotation retired one first, the ingest retries with fresh keys. If the
  ingest committed first, the rotation counts its row.
- **Concurrent searches.** A search re-reads the tenant's key IDs after the query and runs again
  if one appeared. A new key is always stored before any document moves to it, so nothing is
  missed.
- **Legacy rows.**
  - Rows without a keyword list are re-tokenized only if keywords re-extracted from the content
    reproduce the stored tokens exactly.
  - Other rows keep their old search key, which stays searchable and is reported, until they are
    ingested again.
  - Pre-ADR-007 rows are upgraded to the sealed format.
- **Master key.** KMS `GenerateDataKey` creates the master key, and rotation of the customer master
  key happens in KMS. KMS keeps the old key material to decrypt the existing wrapped master key.
  `rotate_kek`, `KeyRotationManager` and `KeyManager.rotate_key` are removed.

### Rationale

**Pros**:
- Retiring or destroying a key is now meaningful: no document references it any more.
- The API keeps serving during a rotation, and a crash at any point is safe to resume.
- No new secret store: the keyword list is sealed like the content.

**Cons**:
- The sealed keyword list makes each row larger. It reveals nothing new to a database reader:
  the token count is already visible.
- Documents ingested with explicit keywords before this change cannot be re-tokenized.
- Each search runs one extra key-ID query.
- One rotation per tenant at a time.

**Alternatives considered**:
- Lazy re-encryption on read: reads would write, which ADR-012 and #39 removed, and the old key could
  never be retired with confidence.
- A scheduler inside the API: key rotation is an operator decision, and a tool is easier to audit.
- Re-wrapping the master key in this code: KMS-side rotation already does it without a migration.

### Consequences

Migration 0005 adds `encrypted_keywords`, indexes on the key-ID columns and `encrypted_ir_key_rotations`.
Operators rotate a tenant with the tool and archive its JSON report. Searches during a rotation compute
tokens under both search keys.

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-01-11 | Architecture Team | Initial ADR log |
| 2.0 | 2026-10-20 | Maintainer | Statuses corrected to match the code; compliance entries marked as targets; FIPS 205 corrected; ADR-011 to ADR-016 added |
| 2.1 | 2026-10-28 | Maintainer | ADR-017 and ADR-018 added; ADR-006, ADR-007 and ADR-014 updated for rotation |

---

## Template for New ADRs

```markdown
## ADR-XXX: [Title]

**Date**: YYYY-MM-DD
**Status**: 🔄 PROPOSED | ✅ ACCEPTED | ❌ REJECTED | ⏸️ SUPERSEDED
**Decision Makers**: [Team/Individual]

### Context
[Problem statement and background]

### Decision
[The decision made]

### Rationale
**Pros**:
- [Advantage 1]

**Cons**:
- [Disadvantage 1]

**Alternatives Considered**:
- [Alternative 1]: [Why rejected]

### Consequences
[Impact on system, performance, operations]

### Compliance Mapping
[Relevant regulations]

### References
[Links to papers, RFCs, documentation]
```

---

**Review Cycle**: Quarterly

[#34]: https://github.com/MysterionRise/encrypted-information-retrieval/issues/34
[#36]: https://github.com/MysterionRise/encrypted-information-retrieval/issues/36
[#37]: https://github.com/MysterionRise/encrypted-information-retrieval/issues/37
[#38]: https://github.com/MysterionRise/encrypted-information-retrieval/issues/38
[#39]: https://github.com/MysterionRise/encrypted-information-retrieval/issues/39
[#40]: https://github.com/MysterionRise/encrypted-information-retrieval/issues/40
[#41]: https://github.com/MysterionRise/encrypted-information-retrieval/issues/41
[#42]: https://github.com/MysterionRise/encrypted-information-retrieval/issues/42
[#44]: https://github.com/MysterionRise/encrypted-information-retrieval/issues/44
[#47]: https://github.com/MysterionRise/encrypted-information-retrieval/issues/47
[#48]: https://github.com/MysterionRise/encrypted-information-retrieval/issues/48
[#49]: https://github.com/MysterionRise/encrypted-information-retrieval/issues/49
