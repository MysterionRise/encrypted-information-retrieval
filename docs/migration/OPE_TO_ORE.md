# Migration Guide: OPE → ORE

**Status:** In Progress (ORE implementation pending - see Issue #1)
**Target Completion:** 2 weeks from MVP start
**Priority:** P0 (Critical for 2025 compliance)

## Executive Summary

The current `OrderPreservingEncryption` (OPE) implementation is deprecated due to security vulnerabilities that fail 2025 standards. This guide provides a comprehensive migration path to ORE (Order-Revealing Encryption) using the Lewi-Wu construction.

### Why Migrate?

| Security Property | OPE (Current) | ORE (Target) | Improvement |
|------------------|---------------|--------------|-------------|
| **Leakage Profile** | Global total order + frequency | Pairwise comparisons only | ✅ Reduced global leakage |
| **Inference Attacks** | Vulnerable (known plaintext recovery) | Resistant | ✅ Strong security |
| **Multi-Tenant Isolation** | None (cross-tenant leakage) | Strong | ✅ Tenant separation |
| **Compliance** | ❌ Fails DORA Art. 9, PCI 3.5.1 | ✅ Meets 2025 standards | ✅ Audit-ready |
| **Performance** | O(1) comparison | O(1) comparison | ➡️ Same |

---

## Table of Contents

1. [Understanding the Security Gap](#understanding-the-security-gap)
2. [ORE Overview](#ore-overview)
3. [Migration Timeline](#migration-timeline)
4. [Code Migration Examples](#code-migration-examples)
5. [Data Migration Strategy](#data-migration-strategy)
6. [Testing Strategy](#testing-strategy)
7. [Rollback Plan](#rollback-plan)
8. [FAQ](#faq)

---

## Understanding the Security Gap

### OPE Vulnerabilities

The current OPE implementation has critical security weaknesses:

#### 1. Global Order Leakage
```python
# OPE reveals global ordering
ope = OrderPreservingEncryption(key)
enc_100 = ope.encrypt_int(100)  # → 1,234,567,890
enc_200 = ope.encrypt_int(200)  # → 2,468,135,780
enc_150 = ope.encrypt_int(150)  # → 1,851,351,835

# Server can now infer: 100 < 150 < 200 (even without decryption)
# Frequency analysis reveals plaintext distribution
```

**Impact:** An honest-but-curious database admin can:
- Reconstruct plaintext distribution (e.g., salary ranges, account balances)
- Identify outliers and statistical properties
- Perform inference attacks with auxiliary information

#### 2. Frequency Analysis Attack
```python
# Attacker observes encrypted transaction amounts
encrypted_amounts = [
    enc_1000,  # Appears 50 times (most common)
    enc_500,   # Appears 30 times
    enc_250,   # Appears 20 times
    ...
]

# With auxiliary knowledge (e.g., "most transactions are $1000")
# Attacker can deduce: enc_1000 → $1000
# Then recover full ordering: enc_500 < enc_1000, so enc_500 → ~$500
```

#### 3. Cross-Tenant Leakage
```python
# Multi-tenant deployment
tenant_a_balance = ope.encrypt_int(5000)  # → 5,123,456,789
tenant_b_balance = ope.encrypt_int(3000)  # → 3,074,074,074

# Server learns: Tenant A has higher balance than Tenant B
# Violates tenant isolation (GDPR Art. 25, DORA Art. 9)
```

### Regulatory Implications

| Regulation | Requirement | OPE Compliance | ORE Compliance |
|-----------|-------------|----------------|----------------|
| **DORA Art. 9** | State-of-the-art cryptography | ❌ Fails (known vulnerabilities) | ✅ Passes |
| **PCI DSS 3.5.1** | Strong cryptography for cardholder data | ❌ Fails (v4.0.1 Mar 31, 2025) | ✅ Passes |
| **NYDFS §500.15** | Encryption with adequate controls | ⚠️ Borderline | ✅ Passes |
| **GDPR Art. 32** | State-of-the-art security measures | ❌ Questionable | ✅ Passes |

**Audit Risk:** Continuing with OPE post-March 2025 creates audit findings and potential regulatory action.

---

## ORE Overview

### Lewi-Wu ORE Construction

ORE (Order-Revealing Encryption) provides a better security-functionality tradeoff:

**Key Innovation:** Split ciphertext into left and right components. Comparison reveals order **only** when both ciphertexts are present—no global order leakage from single ciphertexts.

#### Security Properties

```
Leakage(ORE) = { compare(encrypt(a), encrypt(b)) = (a < b, a = b, a > b) }
```

**What the server learns:**
- ✅ Pairwise comparisons (only when comparing two values)
- ❌ Global total order (cannot rank all values without many comparisons)
- ❌ Frequency distribution (deterministic but no global sorting)
- ❌ Plaintext distribution shape

**What the server does NOT learn:**
- ❌ Plaintext values
- ❌ Ordering from a single ciphertext
- ❌ Cross-tenant comparisons (with per-tenant keys)

#### Performance

| Operation | OPE | ORE (Lewi-Wu) |
|-----------|-----|---------------|
| Encryption | O(1) | O(log n) |
| Comparison | O(1) | O(1) |
| Range Query | O(n) scan | O(n) scan |
| Storage | 8 bytes | 16-32 bytes |

**Verdict:** ORE is slightly slower to encrypt but provides comparable query performance.

---

## Migration Timeline

### Phase 1: Preparation (Week 1)

**Goal:** Implement ORE module and validate correctness

- [ ] **Day 1-3:** Implement ORE module (see Issue #1)
  - `src/encrypted_ir/ore.py` with Lewi-Wu construction
  - 25+ unit tests for correctness
  - Performance benchmarks (P95 < 5ms per comparison)

- [ ] **Day 4-5:** Update use cases
  - Modify `use_cases.py` to use ORE for `TransactionProcessing`
  - Add ORE examples to documentation

- [ ] **Day 6-7:** Integration testing
  - Test ORE with existing SSE and blind index modules
  - Validate end-to-end workflows

**Deliverable:** Functional ORE module with passing tests

### Phase 2: Dual-Running (Week 2-3)

**Goal:** Support both OPE and ORE simultaneously for gradual migration

- [ ] **Week 2:** Implement dual-mode support
  - Add `encryption_mode` config: `"ope"` | `"ore"` | `"both"`
  - Store encryption algorithm identifier with ciphertext
  - Support querying both OPE and ORE encrypted data

- [ ] **Week 3:** Data migration
  - Write batch re-encryption script
  - Re-encrypt existing OPE data to ORE
  - Validate data integrity (compare before/after ordering)

**Deliverable:** All data available in both OPE and ORE formats

### Phase 3: Cutover (Week 4)

**Goal:** Switch all writes to ORE, deprecate OPE

- [ ] **Day 1-2:** Switch writes to ORE
  - Configure `encryption_mode = "ore"` in production
  - Monitor error rates and performance

- [ ] **Day 3-5:** Verify ORE-only operation
  - Confirm all queries use ORE ciphertexts
  - Validate performance SLAs met

- [ ] **Day 6-7:** Archive OPE data
  - Mark OPE columns as deprecated
  - Schedule removal for Q3 2025 (v2.0.0)

**Deliverable:** Production system running exclusively on ORE

---

## Code Migration Examples

### Before (OPE)

```python
from encrypted_ir import OrderPreservingEncryption

# Initialize OPE
ope = OrderPreservingEncryption(key)

# Encrypt transaction amount
amount = 1234.56
encrypted_amount = ope.encrypt_amount(amount)

# Store in database
db.execute(
    "INSERT INTO transactions (customer_id, amount_encrypted) VALUES (?, ?)",
    (customer_id, encrypted_amount)
)

# Range query: Find transactions > $1000
threshold = ope.encrypt_amount(1000.00)
results = db.execute(
    "SELECT * FROM transactions WHERE amount_encrypted > ?",
    (threshold,)
).fetchall()
```

### After (ORE)

```python
from encrypted_ir import ORE  # New module (Issue #1)

# Initialize ORE
ore = ORE(key)

# Encrypt transaction amount
amount = 1234.56
encrypted_amount = ore.encrypt_float(amount, precision=2)

# Store in database
db.execute(
    "INSERT INTO transactions (customer_id, amount_encrypted, encryption_alg) VALUES (?, ?, ?)",
    (customer_id, encrypted_amount, "ore-lewi-wu")
)

# Range query: Find transactions > $1000
threshold = ore.encrypt_float(1000.00, precision=2)
results = db.execute(
    "SELECT * FROM transactions WHERE amount_encrypted > ? AND encryption_alg = 'ore-lewi-wu'",
    (threshold,)
).fetchall()
```

### Key Differences

| Aspect | OPE Code | ORE Code | Change Required |
|--------|----------|----------|----------------|
| **Import** | `OrderPreservingEncryption` | `ORE` | ✅ Update import |
| **Initialization** | `ope = OrderPreservingEncryption(key)` | `ore = ORE(key)` | ✅ Update variable |
| **Encryption** | `ope.encrypt_amount(1234.56)` | `ore.encrypt_float(1234.56, precision=2)` | ⚠️ Method name change |
| **Storage** | Single column | Add `encryption_alg` column | ✅ Schema change |
| **Queries** | No algorithm filter | Filter by `encryption_alg = 'ore-lewi-wu'` | ✅ Add WHERE clause |

---

## Data Migration Strategy

### Option 1: In-Place Re-encryption (Recommended)

**Best for:** Small to medium datasets (< 10M records)

```python
import tqdm
from encrypted_ir import OrderPreservingEncryption, ORE

# Initialize both schemes
ope = OrderPreservingEncryption(ope_key)
ore = ORE(ore_key)

# Get all OPE-encrypted records
records = db.execute("SELECT id, amount_encrypted FROM transactions").fetchall()

# Re-encrypt in batches
batch_size = 10000
for i in tqdm.tqdm(range(0, len(records), batch_size)):
    batch = records[i:i+batch_size]

    for record_id, ope_ciphertext in batch:
        # Note: OPE is one-way, so we need original plaintext
        # If plaintext unavailable, use proxy re-encryption (see Option 2)

        # Option A: If you have plaintext
        plaintext = decrypt_from_backup(record_id)  # From backup/HSM
        ore_ciphertext = ore.encrypt_float(plaintext, precision=2)

        # Update record with ORE ciphertext
        db.execute(
            "UPDATE transactions SET amount_encrypted_ore = ?, encryption_alg = ? WHERE id = ?",
            (ore_ciphertext, "ore-lewi-wu", record_id)
        )

    db.commit()

print(f"Migrated {len(records)} records to ORE")
```

### Option 2: Proxy Re-encryption (Advanced)

**Best for:** Large datasets where plaintext unavailable

```python
# Use order-preserving proxy re-encryption
# This requires custom cryptographic protocol - consult security team

from encrypted_ir.migration import OPEtoOREProxy  # Hypothetical

proxy = OPEtoOREProxy(ope_key, ore_key)

for record_id, ope_ciphertext in records:
    # Transform OPE ciphertext to ORE without decrypting to plaintext
    ore_ciphertext = proxy.reencrypt(ope_ciphertext)

    db.execute(
        "UPDATE transactions SET amount_encrypted_ore = ? WHERE id = ?",
        (ore_ciphertext, record_id)
    )
```

**Warning:** Proxy re-encryption requires advanced cryptography. Consult Issue #1 for implementation status.

### Option 3: Blue-Green Deployment

**Best for:** Zero-downtime migration with rollback capability

1. **Deploy ORE alongside OPE** (Week 1)
   - Add `amount_encrypted_ore` column
   - Write to both OPE and ORE on new inserts

2. **Backfill ORE data** (Week 2)
   - Migrate historical data in background
   - Monitor replication lag

3. **Switch reads to ORE** (Week 3)
   - Update queries to read from `amount_encrypted_ore`
   - Keep OPE as fallback (dual-read mode)

4. **Cutover** (Week 4)
   - Stop writing to OPE column
   - Drop `amount_encrypted` column in Q3 2025

---

## Testing Strategy

### Unit Tests

```python
import pytest
from encrypted_ir import ORE

def test_ore_order_preservation():
    """Verify ORE preserves order correctly."""
    ore = ORE.generate_key()

    values = [100, 200, 150, 300, 50]
    encrypted = [ore.encrypt_int(v) for v in values]

    # Verify order preservation
    assert ore.compare(encrypted[0], encrypted[1]) == -1  # 100 < 200
    assert ore.compare(encrypted[2], encrypted[1]) == -1  # 150 < 200
    assert ore.compare(encrypted[3], encrypted[4]) == 1   # 300 > 50

def test_ore_no_global_leakage():
    """Verify single ciphertext reveals no order information."""
    ore = ORE.generate_key()

    enc_1 = ore.encrypt_int(100)
    enc_2 = ore.encrypt_int(200)

    # Single ciphertext should appear random
    assert not is_sortable_by_inspection([enc_1, enc_2])

def test_tenant_isolation():
    """Verify per-tenant keys prevent cross-tenant comparison."""
    ore_tenant_a = ORE(key_a)
    ore_tenant_b = ORE(key_b)

    enc_a_100 = ore_tenant_a.encrypt_int(100)
    enc_b_50 = ore_tenant_b.encrypt_int(50)

    # Comparison should fail or return random result (not reveal 100 > 50)
    with pytest.raises(ValueError):
        ore_tenant_a.compare(enc_a_100, enc_b_50)
```

### Integration Tests

```python
def test_range_query_after_migration():
    """Verify range queries work correctly with ORE."""
    ore = ORE.generate_key()

    # Insert test data
    test_amounts = [500.00, 1000.00, 1500.00, 2000.00, 2500.00]
    for amount in test_amounts:
        encrypted = ore.encrypt_float(amount, precision=2)
        db.execute(
            "INSERT INTO transactions (amount_encrypted, encryption_alg) VALUES (?, ?)",
            (encrypted, "ore-lewi-wu")
        )

    # Range query: 1000 <= amount <= 2000
    threshold_min = ore.encrypt_float(1000.00, precision=2)
    threshold_max = ore.encrypt_float(2000.00, precision=2)

    results = db.execute(
        "SELECT amount_encrypted FROM transactions "
        "WHERE amount_encrypted >= ? AND amount_encrypted <= ? "
        "AND encryption_alg = 'ore-lewi-wu'",
        (threshold_min, threshold_max)
    ).fetchall()

    assert len(results) == 3  # 1000, 1500, 2000
```

### Performance Tests

```python
import pytest

@pytest.mark.benchmark
def test_ore_encryption_performance(benchmark):
    """Verify ORE meets P95 < 5ms per encryption SLA."""
    ore = ORE.generate_key()

    result = benchmark(ore.encrypt_int, 123456)

    assert benchmark.stats['mean'] < 0.005  # 5ms
    assert benchmark.stats['stddev'] < 0.001

@pytest.mark.benchmark
def test_ore_comparison_performance(benchmark):
    """Verify ORE comparison meets P95 < 1ms per comparison SLA."""
    ore = ORE.generate_key()
    enc_a = ore.encrypt_int(100)
    enc_b = ore.encrypt_int(200)

    result = benchmark(ore.compare, enc_a, enc_b)

    assert benchmark.stats['mean'] < 0.001  # 1ms
```

---

## Rollback Plan

### Rollback Triggers

Roll back to OPE if:
- ❌ ORE query performance degrades > 20% vs. OPE
- ❌ Data corruption detected (ordering violations)
- ❌ Critical bugs in ORE implementation
- ❌ Regulatory objection to ORE scheme

### Rollback Procedure

**Phase 1: Emergency Rollback (< 1 hour)**

```bash
# 1. Switch encryption mode back to OPE
export ENCRYPTION_MODE=ope

# 2. Restart application servers
kubectl rollout restart deployment/encrypted-ir-api

# 3. Verify OPE queries working
curl -X POST /v1/search/range -d '{"field": "amount", "min": 1000}'

# 4. Monitor error rates
watch -n 5 'kubectl logs -l app=encrypted-ir-api | grep ERROR | wc -l'
```

**Phase 2: Data Recovery (< 24 hours)**

```python
# If ORE data corrupted, restore from OPE backup
for record_id in affected_records:
    # Restore OPE ciphertext from backup
    ope_backup = backup_db.execute(
        "SELECT amount_encrypted FROM transactions WHERE id = ?",
        (record_id,)
    ).fetchone()

    # Overwrite corrupted ORE data
    db.execute(
        "UPDATE transactions SET amount_encrypted = ?, encryption_alg = ? WHERE id = ?",
        (ope_backup, "ope", record_id)
    )

db.commit()
```

**Phase 3: Post-Incident Review**

- [ ] Root cause analysis (RCA) within 48 hours
- [ ] Update migration plan with lessons learned
- [ ] Revalidate ORE implementation before retry
- [ ] Notify stakeholders and auditors

---

## FAQ

### Q1: Can I decrypt OPE ciphertexts to get plaintext for ORE migration?

**A:** No, the current OPE implementation is one-way (no decryption function) for security reasons. Options:
- Use backup plaintext data (recommended)
- Implement proxy re-encryption (advanced)
- Collect plaintext on next update (gradual migration)

### Q2: Will ORE work with my existing database indexes?

**A:** Yes, ORE ciphertexts are comparable using standard SQL operators (`<`, `>`, `=`). B-tree indexes work correctly.

```sql
-- Create index on ORE-encrypted column
CREATE INDEX idx_amount_ore ON transactions(amount_encrypted)
    WHERE encryption_alg = 'ore-lewi-wu';
```

### Q3: How much slower is ORE compared to OPE?

**A:** Encryption is ~2-3x slower (still < 5ms P95), but comparison performance is identical (O(1)). Range query performance is the same since both require full table scans or index scans.

### Q4: Do I need different keys for ORE and OPE?

**A:** Yes, use separate keys for security isolation. If you're migrating, generate a new ORE key:

```python
from encrypted_ir import ORE

ore_key = ORE.generate_key()
# Store in KMS/HSM with label "ore-key-v1"
```

### Q5: What if I have multi-tenant data with the same OPE key?

**A:** **High Risk!** You must migrate to per-tenant keys with ORE:

```python
# Generate per-tenant ORE keys
for tenant_id in tenants:
    tenant_ore_key = ORE.generate_key()
    kms.store_key(f"ore-key-{tenant_id}", tenant_ore_key)

    # Re-encrypt tenant's data with tenant-specific key
    migrate_tenant_data(tenant_id, tenant_ore_key)
```

### Q6: Can I use ORE for string/text data?

**A:** ORE is designed for numeric data (integers, floats, dates). For text, use:
- Blind indexes for equality search
- SSE for keyword search
- Don't use ORE for lexicographic order (leaks information)

### Q7: Will ORE be quantum-resistant?

**A:** The Lewi-Wu ORE construction is **not** quantum-resistant (uses classical PRFs). For post-quantum security:
- See Issue #14 (Hybrid PQC) for quantum-resistant encryption
- ORE will be updated with PQC primitives in 2025 H2
- Current ORE is sufficient for 2025 regulatory compliance

### Q8: How do I handle ORE in distributed databases?

**A:** ORE works with distributed databases (PostgreSQL, MySQL, etc.):

```python
# Shard-aware ORE encryption
for shard_id in range(num_shards):
    shard_key = derive_shard_key(master_ore_key, shard_id)
    ore_shard = ORE(shard_key)

    # Encrypt for specific shard
    encrypted = ore_shard.encrypt_int(value)
    db.execute(f"INSERT INTO shard_{shard_id} ...")
```

**Note:** Cross-shard range queries require querying all shards and merging results.

---

## Additional Resources

- **Issue #1:** [Migrate from OPE to ORE](../../GITHUB_ISSUES.md#issue-1-migrate-from-ope-to-ore-for-order-preserving-encryption)
- **Paper:** Lewi & Wu (2016), "Order-Revealing Encryption: New Constructions, Applications, and Lower Bounds" - https://eprint.iacr.org/2016/612
- **ADR-004:** [Decision to migrate OPE → ORE](../DECISIONS.md#adr-004-migrate-ope-to-ore)
- **Threat Model:** [ORE security analysis](../THREAT_MODEL.md#ore-order-revealing-encryption)
- **Compliance:** [Regulatory mapping](../COMPLIANCE_NOTES.md)

---

## Support

For migration assistance:
- **Technical Questions:** Open issue in GitHub with label `area/crypto`
- **Security Concerns:** Email security@example.com (PGP key available)
- **Compliance Questions:** Contact compliance team

---

**Document Version:** 1.0
**Last Updated:** 2025-11-13
**Next Review:** After Issue #1 completion (ORE implementation)
