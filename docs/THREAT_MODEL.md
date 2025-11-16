# Threat Model & Leakage Budget

**Version**: 1.0
**Last Updated**: January 2025
**Scope**: Encrypted Information Retrieval System for Financial Services

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Assets & Protection Goals](#assets--protection-goals)
3. [Adversary Model](#adversary-model)
4. [Cryptographic Primitives & Leakage Profile](#cryptographic-primitives--leakage-profile)
5. [Attack Vectors & Mitigations](#attack-vectors--mitigations)
6. [Leakage Budget by Feature](#leakage-budget-by-feature)
7. [Operational Security Controls](#operational-security-controls)
8. [Residual Risks & Compensating Controls](#residual-risks--compensating-controls)

---

## Executive Summary

This threat model defines the security boundaries, adversary capabilities, and explicit leakage profile of the Encrypted IR system. The system provides **practical encrypted search and computation** for financial services while acknowledging and quantifying unavoidable information leakage.

**Key Security Properties:**
- ✅ **Ciphertext confidentiality**: AES-256 with misuse-resistant AEADs (AES-SIV, AES-GCM)
- ✅ **Authenticity**: All ciphertexts authenticated via MACs/AEAD tags
- ⚠️ **Controlled leakage**: Equality patterns, ordering (where needed), access patterns documented
- ✅ **Key isolation**: Envelope encryption with KMS-backed KEKs
- ⚠️ **Forward/backward privacy**: SSE provides forward privacy; backward privacy roadmapped

**Out of Scope:**
- Perfect access pattern hiding (use PIR/ORAM for zero-leakage requirements)
- Protection against quantum adversaries (PQC hybrid mode planned for 2025 H2)
- Side-channel attacks on client devices
- DDoS/availability attacks

---

## Assets & Protection Goals

### Primary Assets

| Asset | Sensitivity | Protection Goal | Current State |
|-------|-------------|-----------------|---------------|
| **Customer PII** (SSN, account numbers) | **CRITICAL** | Confidentiality + controlled equality leakage | ✅ AES-SIV with blind indexes |
| **Transaction data** (amounts, dates) | **HIGH** | Confidentiality + controlled order leakage | ⚠️ OPE (upgrading to ORE/structured) |
| **Financial documents** (contracts, reports) | **HIGH** | Confidentiality + keyword searchability | ✅ DSSE with forward privacy |
| **Credit scoring models** | **MEDIUM** | Confidentiality + encrypted computation | ✅ CKKS/BFV homomorphic encryption |
| **Encryption keys** (DEKs, KEKs) | **CRITICAL** | Confidentiality + auditability | ✅ Envelope encryption + KMS |
| **Search indexes** | **MEDIUM** | Access pattern minimization | ⚠️ SSE leakage documented |

### Protection Goals Hierarchy

1. **MUST protect**: Plaintext of encrypted data at rest and in transit
2. **SHOULD minimize**: Equality/order/access pattern leakage
3. **NICE TO HAVE**: Zero-leakage query privacy (PIR), side-channel resistance

---

## Adversary Model

### Adversary Capabilities

We consider adversaries with the following powers:

#### A1: Honest-but-Curious Server (Database/Cloud Provider)

**Capabilities:**
- Full access to encrypted database and indexes
- Observes all queries and access patterns over time
- Cannot break AES-256 or compromise KMS
- Can perform frequency analysis, correlation attacks

**Real-World Analogs:** Cloud service providers (AWS, Azure, GCP), compromised DBA, malicious insider with database access

**Defenses:**
- Encrypted data with AES-SIV/AES-GCM
- Blind indexes (HMAC-based) for equality
- SSE with forward privacy
- Padding and dummy queries (optional, performance trade-off)

#### A2: External Attacker (Network Adversary)

**Capabilities:**
- Intercepts network traffic between client and server
- Can replay, drop, or reorder packets
- Cannot break TLS 1.3 or AEAD encryption

**Real-World Analogs:** Nation-state actors, APT groups, ransomware gangs

**Defenses:**
- TLS 1.3 for all client-server communication
- AEAD for all encrypted payloads
- Replay protection via nonces/timestamps in SSE

#### A3: Malicious Insider (Privileged User)

**Capabilities:**
- Legitimate access to some plaintext data
- Can issue queries and observe results
- May attempt to exfiltrate bulk data or keys

**Real-World Analogs:** Rogue employee, compromised admin account, vendor with excessive privileges

**Defenses:**
- Principle of least privilege (RBAC)
- Audit logging of all decrypt/encrypt operations
- Key access policies (KMS conditions, attestation)
- Rate limiting and anomaly detection

#### A4: Future Quantum Adversary (Harvest Now, Decrypt Later)

**Capabilities:**
- Stores encrypted data today
- Will have large-scale quantum computer (2030+)
- Can break RSA-2048, ECDSA P-256

**Real-World Analogs:** Adversaries targeting long-lived data (mortgages, medical records, state secrets)

**Defenses (Planned):**
- **2025 H2**: Hybrid PQC key establishment (Kyber + X25519)
- **2026**: Migration to FIPS 203/204/205 algorithms
- **Now**: Crypto-agile design; algorithm identifiers in ciphertext headers

---

## Cryptographic Primitives & Leakage Profile

### 1. AES-SIV (Deterministic AEAD) - **Equality Searches**

**Primitive:** AES-256-SIV (RFC 5297)
**Library:** `cryptography` v43+
**Use Case:** Account numbers, customer IDs, SSN/Tax IDs

**Security Properties:**
- ✅ **IND-CPA** for random plaintexts
- ✅ **Misuse-resistant**: Nonce reuse safe
- ✅ **Authenticated**: Built-in MAC
- ⚠️ **Deterministic**: Same plaintext → same ciphertext

**Explicit Leakage:**
- **Equality patterns**: `Enc(x) = Enc(y)` reveals `x = y`
- **Frequency**: Distribution of plaintexts visible in ciphertext distribution
- **Bounded inference**: Adversary with auxiliary data can mount inference attacks

**Leakage Mitigation:**
- Use **blind indexes** (HMAC with per-tenant salt/pepper) instead of direct deterministic encryption for most equality searches
- Normalize inputs (case, whitespace, Unicode NFKC) to reduce spurious matches
- Periodic index key rotation (90 days) to limit long-term frequency analysis

**Attack Resistance:**
| Attack Type | Resistance | Notes |
|-------------|-----------|-------|
| Brute force | ✅ Strong | 256-bit key |
| Frequency analysis | ⚠️ Moderate | Mitigated by blind indexes + salting |
| Inference (w/ aux data) | ⚠️ Weak-Moderate | Depends on plaintext entropy |
| Nonce reuse | ✅ Strong | SIV mode safe |

### 2. Blind Indexes (HMAC-SHA256) - **Equality Searches (Preferred)**

**Primitive:** HMAC-SHA256 with per-tenant salt
**Use Case:** Equality search without revealing full ciphertext determinism

**Security Properties:**
- ✅ **Collision-resistant** (2^128 security for truncated HMAC-256-128)
- ✅ **Preimage-resistant**
- ⚠️ **Equality-revealing**: `HMAC(x) = HMAC(y)` reveals `x = y` within scope

**Explicit Leakage:**
- **Equality within tenant**: Indexes collision only within same tenant scope
- **Frequency (scoped)**: Limited to tenant's dataset, not global
- **No order information**: Unlike OPE, reveals only equality

**Leakage Mitigation:**
- Per-tenant salt/pepper (stored in KMS)
- Input normalization (canonical form)
- Optional: Keyed hash per field type (account_index_key ≠ SSN_index_key)

### 3. Dynamic SSE (Searchable Symmetric Encryption) - **Keyword Search**

**Primitive:** DSSE with forward privacy (based on Σoφoς-like constructions)
**Library:** Custom implementation over HMAC + AES-GCM
**Use Case:** Document management, email archives, knowledge bases

**Security Properties:**
- ✅ **Forward privacy**: New document additions unlinkable to past queries
- ⚠️ **Backward privacy**: Deletes leak (roadmapped for P1)
- ✅ **Replay protection**: Nonce-based freshness

**Explicit Leakage:**
- **Search pattern**: Which queries repeat over time
- **Access pattern**: Which documents match a query
- **Result size**: Number of matching documents
- **Update pattern**: Timing and frequency of index updates

**Leakage Mitigation:**
- Padding (optional): Pad result sets to fixed sizes (e.g., next power of 2)
- Dummy queries: Client issues random cover queries (performance vs. privacy trade-off)
- **PIR mode** (feature flag): Use Private Information Retrieval for zero-leakage queries at 10-100x latency cost

**Attack Resistance:**
| Attack Type | Resistance | Notes |
|-------------|-----------|-------|
| Keyword guessing | ⚠️ Moderate | Adversary with query logs + aux data can infer keywords |
| Query recovery | ⚠️ Weak-Moderate | File-injection attacks (IKK, LEAP-style) possible if adversary controls documents |
| Forward privacy | ✅ Strong | Updates unlinkable to past queries |
| Backward privacy | ❌ Weak | Deletes currently leak (P1 upgrade) |

**Known Attacks & References:**
- **IKK attack** (Islam et al., NDSS 2012): File-injection attack on static SSE
- **LEAP attack** (Cash et al., CCS 2015): Leakage abuse on dynamic SSE
- **Mitigation**: Our DSSE provides forward privacy; recommend PIR mode for high-sensitivity collections

### 4. Order-Revealing Encryption (ORE) - **Range Queries** [UPGRADE IN PROGRESS]

**Current:** Simplified OPE (PRF-based linear mapping)
**Target:** Lewi-Wu ORE or structured encryption with bucketed B-trees
**Use Case:** Transaction amounts, dates, account balances

**Security Properties (Current OPE):**
- ⚠️ **Order-revealing**: `Enc(a) < Enc(b)` reveals `a < b`
- ⚠️ **Frequency-leaking**: Distribution visible
- ⚠️ **Inference-vulnerable**: Adversary can recover approximate plaintexts via sorting attacks

**Explicit Leakage (Current):**
- **Full order**: Complete plaintext ordering revealed
- **Distribution**: Ciphertext distribution mirrors plaintext distribution
- **Inference**: Sorting attack + auxiliary data → plaintext recovery

**UPGRADE PLAN (P0):**
Replace with:
1. **Lewi-Wu ORE**: Leaks only order, not approximate values
2. **Structured Encryption**: Bucketed range trees with padding + client-side post-filtering
3. **TEE-assisted**: Decrypt ranges inside AWS Nitro Enclave for zero-leakage alternative

**Leakage Mitigation (Post-Upgrade):**
- ORE: Leaks order but not distribution shape
- Structured encryption: Leaks bucket access, not individual comparisons
- TEE: Zero server-side leakage; attested key release

**Attack Resistance (Post-ORE Upgrade):**
| Attack Type | Resistance | Notes |
|-------------|-----------|-------|
| Sorting attack | ⚠️ Moderate | ORE leaks order; mitigated by coarse buckets |
| Frequency analysis | ⚠️ Moderate | ORE improves over OPE; bucketing further reduces |
| Range reconstruction | ⚠️ Weak | Adversary can estimate distribution |

### 5. Homomorphic Encryption (CKKS/BFV) - **Encrypted Computation**

**Primitive:** CKKS (approx. arithmetic), BFV (exact integers)
**Library:** TenSEAL (Microsoft SEAL wrapper)
**Use Case:** Credit scoring, risk analytics, encrypted ML inference

**Security Properties:**
- ✅ **IND-CPA**: Semantic security under RLWE/LWE assumptions
- ✅ **Zero server-side leakage**: Server never sees plaintext
- ⚠️ **Ciphertext size**: Large (100KB+ per encrypted vector)
- ⚠️ **Computation structure**: Server learns model topology

**Explicit Leakage:**
- **Model structure**: Number/type of operations (add, mult) visible
- **Computation timing**: Depth of circuit leaks via latency
- **Result size**: Output ciphertext size hints at result magnitude

**Leakage Mitigation:**
- **Constant-time operations**: Use fixed-depth circuits where possible
- **Ciphertext packing**: Batch multiple values per ciphertext (SIMD)
- **Rate limiting**: Prevent timing analysis via repeated queries
- **TEE option**: Decrypt results inside enclave for sensitive outputs

**Attack Resistance:**
| Attack Type | Resistance | Notes |
|-------------|-----------|-------|
| Ciphertext-only | ✅ Strong | IND-CPA under RLWE |
| Side-channel (timing) | ⚠️ Moderate | Constant-time library; circuit depth may leak |
| Model extraction | ⚠️ Moderate | Topology visible; weights encrypted |

---

## Attack Vectors & Mitigations

### AV1: Frequency Analysis on Deterministic Ciphertexts

**Attack:** Adversary builds histogram of ciphertext frequencies, correlates with known plaintext distribution.

**Likelihood:** HIGH (honest-but-curious server)
**Impact:** MEDIUM (reveals common values)

**Mitigations:**
1. ✅ **Use blind indexes** instead of direct deterministic encryption
2. ✅ Per-tenant salts (limits correlation across tenants)
3. ⚠️ Plaintext padding (adds complexity; roadmapped)
4. ✅ Periodic index key rotation (breaks long-term frequency tracking)

**Residual Risk:** LOW-MEDIUM (post-mitigation)

### AV2: Access Pattern Analysis on SSE Queries

**Attack:** Adversary logs which documents are accessed for each query, builds co-occurrence graph to infer keywords.

**Likelihood:** MEDIUM-HIGH (honest-but-curious server)
**Impact:** MEDIUM-HIGH (can reveal query keywords with auxiliary data)

**Mitigations:**
1. ✅ **Forward privacy**: New documents unlinkable to past queries
2. ⚠️ Dummy queries (optional, performance cost)
3. ⚠️ Padding result sets (roadmapped for P1)
4. ✅ **PIR mode** (feature flag): Zero-leakage alternative for sensitive collections

**Residual Risk:** MEDIUM (SSE mode), LOW (PIR mode)

**References:**
- Cash et al., "Leakage-Abuse Attacks Against Searchable Encryption", CCS 2015
- Islam et al., "Access Pattern Disclosure on Searchable Encryption", NDSS 2012

### AV3: Inference Attacks on Order-Preserving Encryption

**Attack:** Adversary sorts encrypted values, uses auxiliary data (e.g., income distributions) to recover approximate plaintexts.

**Likelihood:** MEDIUM (requires auxiliary data)
**Impact:** HIGH (plaintext recovery)

**Mitigations:**
1. 🔄 **UPGRADE to ORE** (P0): Reduces leakage vs. classical OPE
2. 🔄 **Structured encryption** (P0): Bucketed range trees with padding
3. ⚠️ **TEE-assisted** (P1): Decrypt ranges inside Nitro Enclave

**Residual Risk:** HIGH (current OPE), MEDIUM (post-ORE upgrade)

**References:**
- Naveed et al., "Inference Attacks on Property-Preserving Encrypted Databases", CCS 2015
- Grubbs et al., "Leakage-Abuse Attacks Against Order-Revealing Encryption", S&P 2017

### AV4: Key Compromise (DEK/KEK)

**Attack:** Adversary exfiltrates data encryption keys or KMS master keys.

**Likelihood:** LOW (with proper KMS policies)
**Impact:** CRITICAL (full plaintext recovery)

**Mitigations:**
1. ✅ **Envelope encryption**: DEKs encrypted by KMS-backed KEKs
2. ✅ **HSM-backed KEKs**: FIPS 140-3 Level 3 modules (AWS KMS, CloudHSM)
3. ✅ **Key access policies**: IAM conditions, attestation (TEE), MFA
4. ✅ **Audit logging**: CloudTrail for all KMS operations
5. ✅ **Rotation**: DEK rotation every 90 days; KEK rotation annually
6. ✅ **Principle of least privilege**: Separate keys per tenant/dataset

**Residual Risk:** LOW (with controls)

### AV5: Side-Channel Attacks (Timing, Cache)

**Attack:** Adversary infers plaintext via timing differences in crypto operations or cache access patterns.

**Likelihood:** LOW (requires co-location or local access)
**Impact:** MEDIUM (key bit leakage)

**Mitigations:**
1. ✅ **Constant-time libraries**: `cryptography` uses constant-time AES
2. ⚠️ **HE timing**: SEAL operations not constant-time; fix via padding/dummy ops (roadmapped)
3. ⚠️ **Input validation**: Prevent timing oracles via length/format checks

**Residual Risk:** LOW (AES/HMAC), MEDIUM (HE)

### AV6: Quantum Attacks (Harvest Now, Decrypt Later)

**Attack:** Adversary stores encrypted data today, decrypts with quantum computer post-2030.

**Likelihood:** LOW (short-term), MEDIUM (10+ years)
**Impact:** CRITICAL (for long-lived data)

**Mitigations:**
1. 🔄 **Hybrid PQC** (2025 H2): Kyber + X25519 key establishment
2. 🔄 **FIPS 203/204/205** (2026): Migration to NIST-approved PQC
3. ✅ **Crypto-agility**: Algorithm IDs in ciphertext headers; versioned keys

**Residual Risk:** MEDIUM (pre-PQC), LOW (post-PQC hybrid)

---

## Leakage Budget by Feature

| Feature | Leaked Information | Leakage Severity | Mitigation | Residual Risk |
|---------|-------------------|------------------|------------|---------------|
| **Equality (blind index)** | Equality within tenant, scoped frequency | MEDIUM | Per-tenant salts, rotation | LOW-MEDIUM |
| **Keyword search (SSE)** | Query repetition, access patterns, result sizes | MEDIUM-HIGH | Forward privacy, PIR mode | MEDIUM (SSE), LOW (PIR) |
| **Range queries (OPE→ORE)** | Full order (OPE) → order only (ORE) | HIGH (OPE) → MEDIUM (ORE) | Upgrade to ORE/buckets, TEE | HIGH (now), MEDIUM (post-upgrade) |
| **HE computation** | Model structure, timing, result sizes | LOW-MEDIUM | Constant-time, TEE decryption | LOW |
| **Key management** | Key access timestamps, rotation events | LOW | Audit logging, anomaly detection | LOW |

---

## Operational Security Controls

### 1. Key Management (NIST SP 800-57 Part 1 Rev. 5)

- ✅ **KEK**: Stored in AWS KMS/CloudHSM (FIPS 140-3 Level 3)
- ✅ **DEK**: Per-tenant, per-dataset; re-wrapped on rotation
- ✅ **Rotation**: DEK every 90 days, KEK annually
- ✅ **Audit**: CloudTrail logs all Encrypt/Decrypt/GenerateDataKey calls
- ✅ **Access control**: IAM policies with MFA, attestation conditions (for TEE)

### 2. Network Security

- ✅ **TLS 1.3**: All client-server communication
- ✅ **Certificate pinning**: Mitigate MITM
- 🔄 **mTLS** (P1): Mutual authentication for API clients

### 3. Audit & Monitoring

- ✅ **Audit trail**: Every encrypt/decrypt logged with (timestamp, user, key_id, operation)
- ✅ **Anomaly detection**: Rate limits; alert on unusual key access patterns
- ⚠️ **Immutable ledger** (P2): QLDB for tamper-proof audit logs

### 4. Access Control (RBAC)

- ✅ **Principle of least privilege**: Users/services get minimal necessary permissions
- ✅ **Tenant isolation**: Keys and indexes separated per tenant
- ✅ **MFA**: Required for key management operations

### 5. Incident Response

- ✅ **Crypto-shredding**: Delete keys → data unrecoverable
- ✅ **Rotation on breach**: Emergency DEK rotation procedure documented
- ⚠️ **Breach notification** (P1): Automated compliance reporting (GDPR, DORA)

---

## Residual Risks & Compensating Controls

### High-Priority Residual Risks

1. **OPE Inference Attacks** (until P0 upgrade completes)
   - **Compensating Controls**: Use only for non-sensitive ranges (dates, timestamps), not financial amounts
   - **Monitoring**: Alert on unusual range query patterns
   - **Timeline**: ORE upgrade by 2025-Q1

2. **SSE Access Pattern Leakage**
   - **Compensating Controls**: PIR mode for high-sensitivity collections; dummy queries
   - **Monitoring**: Rate-limit queries; detect scraping attempts
   - **Accept Risk**: For non-PII documents (public filings, marketing materials)

3. **Quantum Threats to Current AES-256**
   - **Compensating Controls**: Prioritize PQC for long-lived data (mortgages, contracts)
   - **Timeline**: Hybrid PQC by 2025-Q3; full migration by 2026-Q2
   - **Accept Risk**: AES-256 secure against classical adversaries; quantum threats >10 years out

### Accepted Risks (With Justification)

1. **Side-channel attacks**: Low likelihood without co-location; monitoring for anomalous latencies
2. **DDoS/availability**: Out-of-scope; handled by infrastructure layer (WAF, rate limiting)
3. **Malicious client**: Cannot prevent authorized users from exfiltrating data they can decrypt; rely on DLP, CASB

---

## Compliance Mapping

| Regulation | Requirement | Implementation | Gap |
|------------|-------------|----------------|-----|
| **PCI DSS v4.0** | Encrypt cardholder data at rest | ✅ AES-256-GCM/SIV | None |
| **PCI DSS v4.0** | Key rotation (3.6.4) | ✅ 90-day DEK rotation | None |
| **GDPR Art. 32** | State-of-the-art encryption | ✅ AEAD, 256-bit keys | None |
| **GDPR Art. 32** | Pseudonymization | ✅ Blind indexes | None |
| **DORA Art. 9** | ICT risk management | ✅ Threat model, audit logs | ⚠️ Incident response automation (P1) |
| **NYDFS 23 NYCRR § 500.15** | Encryption of nonpublic info | ✅ AES-256 | None |
| **NIST SP 800-57** | Key management best practices | ✅ Envelope encryption, HSM | None |

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-01-11 | Security Architecture Team | Initial threat model for MVP |

---

## References

1. NIST SP 800-57 Part 1 Rev. 5, "Recommendation for Key Management"
2. RFC 5297, "Synthetic Initialization Vector (SIV) Authenticated Encryption"
3. Cash et al., "Leakage-Abuse Attacks Against Searchable Encryption", CCS 2015
4. Naveed et al., "Inference Attacks on Property-Preserving Encrypted Databases", CCS 2015
5. NIST FIPS 203/204/205, "Module-Lattice-Based Key-Encapsulation/Digital Signature Standards", 2024
6. EU Regulation 2022/2554 (DORA), "Digital Operational Resilience Act"
7. PCI Security Standards Council, "PCI DSS v4.0.1", 2024

---

**Classification**: Internal Use Only
**Contact**: security-architecture@company.com
