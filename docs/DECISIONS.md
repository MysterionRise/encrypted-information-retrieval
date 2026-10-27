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
- ⚠️ **Slightly slower**: ~20% overhead vs. AES-GCM (negligible for our latency requirements)

**Alternatives Considered**:
- **AES-GCM with fixed nonce**: Rejected (catastrophic if nonce reused accidentally)
- **AES-GCM-SIV**: Acceptable alternative; AES-SIV chosen for maturity
- **Format-Preserving Encryption (FF1)**: Use only where format constraints exist (e.g., legacy systems requiring specific field widths)

### Consequences

- **Security**: Strong confidentiality and authenticity; controlled equality leakage documented in THREAT_MODEL.md
- **Performance**: 2-5x slower than plaintext lookups (acceptable for <10ms latency requirement)
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
**Status**: Accepted. Implemented in `blind_index.py` as a library primitive. Not used by the durable document path. Known defects are tracked in [#37].
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
- **Performance**: HMAC computation ~1-2ms; minimal overhead
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
- ✅ **Practical performance**: 20-50ms search latency @ 10k documents
- ✅ **Well-studied**: Σoφoς-style constructions analyzed in literature

**Cons**:
- ⚠️ **Access pattern leakage**: Which documents match a query
- ⚠️ **Search pattern leakage**: Query repetition visible
- ⚠️ **No backward privacy** (MVP): Deletes leak (roadmapped for P1)

**Alternatives Considered**:
- **Static SSE**: Rejected (no forward privacy; vulnerable to LEAP-style attacks)
- **ORAM**: Rejected (100-1000x overhead; impractical for FS latency requirements)
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
**Status**: Not achieved as written. `ore.py` implements a CLWW-style prefix ORE, not Lewi-Wu. Its comparison needs no key, so its order leakage equals OPE's ([#34]). OPE is still used by the demo use cases; removal is [#37].
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
- **Performance**: ORE comparison ~30ms (vs. 10ms for OPE)
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
- ⚠️ **Performance**: 100-1000x slower than plaintext
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
**Status**: Partially implemented. A single app master key can be unwrapped through AWS KMS at startup (`master_key.py`, tested with mocks only), and per-tenant keys are wrapped locally under it. No HSM, CloudHSM or CloudTrail integration exists in this repository.
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
- ✅ **Audit logging**: CloudTrail integration
- ✅ **Per-tenant isolation**: Separate DEKs per tenant
- ✅ **Rotation**: Re-wrap DEKs without KEK change

**Cons**:
- ⚠️ **Cloud dependency**: Requires AWS/Azure/GCP KMS
- ⚠️ **Cost**: ~$1/month per CMK + API call charges
- ⚠️ **Latency**: KMS API call adds ~50ms (mitigated by DEK caching)

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
- **Performance**: DEK cache (5-minute TTL) → 2ms decrypt (cached), 50ms (cache miss)
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

**Date**: 2025-01-11
**Status**: Accepted, not implemented. The ciphertext header below does not exist. Document ciphertexts are `iv || tag || ciphertext` with no header or associated data ([#40]).
**Decision Makers**: Security Architecture Team

### Context

Cryptographic algorithms have finite lifespans. We must prepare for:
1. **Algorithm breaks**: Unexpected cryptanalysis
2. **Post-quantum migration**: NIST FIPS 203/204/205 (2024)
3. **Compliance changes**: Future regulatory requirements

### Decision

**Design for crypto-agility: include algorithm identifiers in ciphertext headers; support versioned keys.**

### Rationale

**Pros**:
- ✅ **Future-proof**: Seamless algorithm migration
- ✅ **Gradual rollout**: Support old + new algorithms simultaneously
- ✅ **Audit trail**: Track which algorithm version encrypted each record
- ✅ **Compliance**: Meet PQC migration mandates

**Cons**:
- ⚠️ **Complexity**: Versioning logic in encrypt/decrypt paths
- ⚠️ **Storage overhead**: ~16 bytes per ciphertext for header

**Alternatives Considered**:
- **Fixed algorithms**: Rejected (requires full data re-encryption for algorithm changes)
- **External mapping**: Rejected (lose self-describing property)

### Ciphertext Format

```
┌─────────────────────────────────────────────────────┐
│ Encrypted Ciphertext Structure                      │
├─────────────────────────────────────────────────────┤
│ [Version: 1 byte]                                   │
│ [Algorithm ID: 1 byte]                              │
│   - 0x01: AES-256-SIV                               │
│   - 0x02: AES-256-GCM                               │
│   - 0x03: ChaCha20-Poly1305                         │
│   - 0x10: Kyber768 + AES-256-GCM (PQC hybrid)       │
│ [Key ID: 16 bytes]                                  │
│ [IV/Nonce: variable, algorithm-dependent]           │
│ [Ciphertext: variable]                              │
│ [Authentication Tag: 16 bytes]                      │
└─────────────────────────────────────────────────────┘
```

### Consequences

- **Migration**: Decrypt with old algorithm, re-encrypt with new (lazy migration)
- **Backward compatibility**: Old ciphertexts remain valid until rotation
- **PQC readiness**: Smooth transition to Kyber/Dilithium in 2025-2026

### Compliance Mapping

- Target: **NIST PQC migration**: Algorithm agility enables hybrid mode
- Target: **PCI DSS 12.3.4**: Documented cryptographic architecture

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
- ⚠️ **Performance**: 10-100x slower than SSE
- ⚠️ **Database size limit**: Practical for <1M records
- ⚠️ **Implementation complexity**: Requires specialized library (SealPIR, SimplePIR)

**Alternatives Considered**:
- **ORAM**: Rejected (1000x+ overhead)
- **TEE-only**: Complementary; PIR provides no-trust-anchor alternative

### Implementation Plan

1. **Phase 1 (P1)**: Integrate SimplePIR for single-server PIR
2. **Phase 2 (P2)**: Add DoublePIR for improved throughput
3. **Use Cases**: Sanctions screening, PEP lists, watchlists

### Consequences

- **Performance**: 100-500ms per query (vs. 20ms for SSE)
- **Scalability**: Per-server capacity: ~10 QPS (PIR) vs. 500 QPS (SSE)
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
- ⚠️ **Performance**: ~10% overhead vs. non-enclave
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
- **Performance**: 10% overhead; acceptable for high-sensitivity operations
- **Operational**: Require attestation flow; document in runbooks

### References

- [AWS Nitro Enclaves](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html)
- [Azure Confidential Computing](https://azure.microsoft.com/en-us/solutions/confidential-compute/)

---

## ADR-010: Post-Quantum Cryptography Roadmap

**Date**: 2025-01-11
**Status**: Research module only. ML-KEM, ML-DSA and a hybrid KEM exist in `post_quantum.py` (pqcrypto 0.4) and are not used by the durable path. The hybrid combiner is not X-Wing ([#38]).
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
- ⚠️ **Performance**: PQC key operations ~2-10x slower
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

- **Performance**: 5-10% overhead (hybrid mode)
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
- The service is single-process today (in-memory rate limiter and key cache). Multi-replica correctness
  is tracked in [#39] and [#47].

---

## ADR-012: AES-GCM Documents with HMAC Keyword Tokens on the Durable Path

**Date**: 2026-07-06 (recorded 2026-10-20)
**Status**: Accepted. Implemented in `DocumentService` through `SearchableEncryption`.

### Context

ADR-001 (AES-SIV), ADR-003 (forward-private DSSE) and ADR-004 (ORE) describe primitives that exist as
library or research code. The durable path needed one construction that is standard, testable and simple
to reason about.

### Decision

Encrypt document bodies with AES-256-GCM under a per-tenant key. Index them with deterministic
`HMAC-SHA256(per-tenant search key, keyword)` tokens stored one row per keyword per document.

### Consequences

- The leakage is explicit and documented per endpoint: keyword equality and frequency within a tenant,
  query repetition, result sizes and access patterns.
- No forward or backward privacy.
- Binding ciphertexts to their tenant and document with associated data is tracked in [#40].

---

## ADR-013: OIDC/JWKS in Production, Explicit Dev Auth Otherwise

**Date**: 2026-07-06 (recorded 2026-10-20)
**Status**: Accepted. Implemented. Hardening is tracked in [#41].

### Decision

- **Production mode** (`ENCRYPTED_IR_ENV=prod`):
  - Requires OIDC issuer, audience and JWKS URL.
  - Verifies RS256 bearer tokens against the JWKS.
  - Takes the tenant and roles from configurable claims.
  - Rejects dev auth.
- **Other modes:** an explicit dev API key and dev HS256 tokens exist so the local demo needs no identity
  provider.

### Consequences

- The local demo works without cloud accounts.
- Dev auth is on by default outside production, with a public default HS256 secret.
- `exp` is not yet required.
- [#41] tightens both. Live IdP evidence is [#48].

---

## ADR-014: One KMS-Wrapped App Master Key, Locally Wrapped Tenant Keys

**Date**: 2026-07-06 (recorded 2026-10-20)
**Status**: Accepted. Implemented. KMS is tested with mocks only; live evidence is [#49].

### Decision

One application master key per deployment. Production mode unwraps it once at startup with AWS KMS
`Decrypt`; dev reads it from an environment variable. Per-tenant document and search keys are generated
locally and stored AES-GCM-wrapped under that master key.

### Consequences

- One KMS call per process start instead of one per request.
- The master key stays in process memory, so a host compromise exposes every tenant (THREAT_MODEL A3).
- Re-encrypting documents on rotation is not implemented ([#42]).

---

## ADR-015: Quarantine Research Modules

**Date**: 2026-10-20
**Status**: Accepted. Implementation tracked in [#37].

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

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-01-11 | Architecture Team | Initial ADR log |
| 2.0 | 2026-10-20 | Maintainer | Statuses corrected to match the code; compliance entries marked as targets; FIPS 205 corrected; ADR-011 to ADR-016 added |

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
[#47]: https://github.com/MysterionRise/encrypted-information-retrieval/issues/47
[#48]: https://github.com/MysterionRise/encrypted-information-retrieval/issues/48
[#49]: https://github.com/MysterionRise/encrypted-information-retrieval/issues/49
