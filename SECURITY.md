# Security Policy

## Project Security Posture

This repository is a portfolio-grade, production-oriented prototype for
privacy-preserving retrieval. It contains real cryptographic building blocks
and extensive tests, but it is **not** externally audited and should not be
treated as a production cryptography product without independent review,
operational hardening, and threat-specific validation.

The Docker Compose workflow is intended for local evaluation of encrypted
document retrieval and RAG-ready API behavior. Demo authentication, local
master keys, and auto-created tables are deliberately convenient defaults,
not production controls.

## Supported Versions

Security fixes are tracked for the following prototype versions:

| Version | Supported          | Status |
| ------- | ------------------ | ------ |
| 1.0.x   | :white_check_mark: | Current prototype release |
| < 1.0   | :x:                | Development versions not supported |

**Note:** OPE (Order-Preserving Encryption) is retained for compatibility demos
and should not be used for sensitive range queries. Prefer the ORE prototype or
a vetted structured-encryption/TEE design after review.

---

## Reporting a Vulnerability

We appreciate your help in making this project more secure! If you discover a security vulnerability, please follow these steps:

### 🔒 Private Disclosure Process

**DO NOT** open a public GitHub issue for security vulnerabilities. Instead:

1. **Email:** Send vulnerability details to **security@example.com** (update with actual email)
2. **PGP Encryption (Recommended):** Encrypt sensitive details with our PGP key:
   ```
   Fingerprint: XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX
   Key available at: https://keybase.io/encrypted_ir_team
   ```
3. **Subject Line:** `[SECURITY] Brief description of vulnerability`

### 📋 What to Include in Your Report

A good security report should include:

- **Description:** Clear description of the vulnerability
- **Impact:** Potential impact (data leakage, unauthorized access, etc.)
- **Affected Versions:** Which versions are vulnerable
- **Reproduction Steps:** Detailed steps to reproduce the issue
- **Proof of Concept:** Code snippet or example (if applicable)
- **Suggested Fix:** Proposed remediation (optional but helpful)
- **Credit:** How you'd like to be credited in the advisory (optional)

### 📧 Email Template

```
Subject: [SECURITY] Cryptographic vulnerability in blind index module

Description:
[Clear description of the vulnerability]

Impact:
[Potential security impact - e.g., "Allows tenant isolation bypass"]

Affected Versions:
[e.g., "All versions prior to 1.0.5"]

Reproduction Steps:
1. [Step 1]
2. [Step 2]
3. [Observe vulnerability]

Proof of Concept:
```python
# Example code demonstrating the vulnerability
```

Suggested Fix:
[Optional - your proposed remediation]

Credit:
[How you'd like to be credited]
```

---

## Response Timeline

We are committed to addressing security vulnerabilities promptly:

| Severity    | Response Time | Fix Target  | Public Disclosure |
|-------------|---------------|-------------|-------------------|
| **Critical** | 24 hours     | 7 days      | After patch release |
| **High**     | 48 hours     | 14 days     | After patch release |
| **Medium**   | 7 days       | 30 days     | After patch release |
| **Low**      | 14 days      | 60 days     | After patch release |

### Severity Definitions

- **Critical:** Remote code execution, key compromise, complete authentication bypass
- **High:** Privilege escalation, significant data leakage, cryptographic weakness
- **Medium:** Partial information disclosure, denial of service, side-channel attacks
- **Low:** Security-relevant bugs with low exploitability

---

## Security Update Process

When we receive a valid security report:

1. **Acknowledgment:** We'll confirm receipt within the response timeline
2. **Validation:** Our security team will validate the vulnerability
3. **Assessment:** We'll assess severity and exploitability
4. **Fix Development:** We'll develop and test a fix
5. **Coordinated Disclosure:** We'll work with you on disclosure timing
6. **Patch Release:** We'll release a security patch
7. **Public Advisory:** We'll publish a security advisory (with credit)
8. **CVE Assignment:** For high/critical issues, we'll request a CVE

### Communication

We'll keep you updated throughout the process:
- Confirmation of receipt (within response timeline)
- Validation results (within 5 business days)
- Fix timeline estimate (within 7 business days)
- Pre-release notification (24 hours before public disclosure)

---

## Security Advisories

Published security advisories will be available at:
- **GitHub Security Advisories:** https://github.com/MysterionRise/encrypted-information-retrieval/security/advisories
- **SECURITY_ADVISORIES.md:** Historical log of all advisories

---

## Known Security Considerations

### ⚠️ Current Limitations (v1.0.x)

#### 1. OPE (Order-Preserving Encryption) - DEPRECATED

**Status:** Deprecated, retained only for compatibility demos

**Issue:** Current OPE implementation leaks global order and frequency information.

**Impact:**
- Honest-but-curious server can infer plaintext distribution
- Vulnerable to frequency analysis attacks
- Cross-tenant information leakage in multi-tenant deployments

**Mitigation:**
- **Immediate:** Avoid using OPE for sensitive data
- **Short-term:** Migrate to blind indexes for equality search
- **Long-term:** Migrate to ORE (Lewi-Wu construction) - see Issue #1

**References:**
- Migration guide: `docs/migration/OPE_TO_ORE.md`
- Threat model: `docs/THREAT_MODEL.md#ope-order-preserving-encryption`

#### 2. SSE (Searchable Symmetric Encryption) - Forward Privacy

**Status:** Prototype implementations available

**Issue:** The legacy `SearchableEncryption` facade is a simple AES-GCM +
deterministic HMAC-token index. `ForwardPrivateSSE` and `BackwardPrivateIndex`
demonstrate stronger designs, but they are prototype implementations and have
not been externally audited.

**Impact:**
- Server may link new document additions to past search queries
- Potential for statistical inference attacks on dynamic datasets

**Mitigation:**
- Use SSE only for semi-static datasets
- Periodic re-encryption of search indexes
- **Fix coming:** Issue #5 (Forward privacy enhancement - 1 week)

**References:**
- Threat model: `docs/THREAT_MODEL.md#sse-searchable-symmetric-encryption`

#### 3. Key Management - Envelope Encryption

**Status:** Prototype AWS KMS custody path implemented

**Issue:** The API can unwrap an application master key through AWS KMS at
startup, and production mode rejects raw master-key configuration. This is a
serious custody improvement, but it is not yet a fully operated key-management
program: IAM policies, CloudTrail retention, key rotation runbooks, break-glass
procedures, and external review remain outside this repository.

**Impact:**
- Raw key exposure is reduced in production mode
- Runtime plaintext master-key residency still needs operational controls
- Rotation and incident-response evidence still need deployment runbooks

**Mitigation:**
- Use `ENCRYPTED_IR_KMS_PROVIDER=aws` with `ENCRYPTED_IR_ENCRYPTED_MASTER_KEY_B64`
- Deny raw `ENCRYPTED_IR_MASTER_KEY_B64` in production
- Restrict KMS decrypt permissions to the API runtime role
- Enable CloudTrail and alert on unexpected KMS decrypt events
- Add a deployment-specific key rotation and recovery runbook before production use

**References:**
- Architecture: `docs/ARCHITECTURE.md#key-management`

---

## Security Best Practices

### For Users of This Library

#### 1. Key Management

✅ **DO:**
- Generate keys using cryptographically secure random number generators (`os.urandom(32)`)
- Store keys separately from encrypted data
- Use per-tenant keys for multi-tenant deployments
- Rotate keys according to your compliance requirements (e.g., 90 days for DEKs)
- Use environment variables or secret management services (AWS Secrets Manager, HashiCorp Vault)

❌ **DON'T:**
- Hard-code keys in source code
- Store keys in version control
- Reuse keys across different environments (dev/staging/prod)
- Share keys between tenants

#### 2. Encryption Scheme Selection

✅ **DO:**
- Use **blind indexes** for equality search (tenant-isolated, secure)
- Use **ORE** (after Issue #1) for range queries (pairwise comparison only)
- Use **AES-SIV** for deterministic encryption (misuse-resistant)
- Use **SSE** for keyword search (with forward privacy after Issue #5)
- Use **HE** for computations on encrypted data (CKKS for approximate, BFV for exact)

❌ **DON'T:**
- Use OPE for new deployments (deprecated, global order leakage)
- Use deterministic encryption for high-entropy data without additional protection
- Mix encryption schemes without understanding leakage implications

#### 3. Deployment Security

✅ **DO:**
- Enable TLS/HTTPS for all API communication (after Issue #4)
- Implement rate limiting to prevent brute-force attacks
- Use per-tenant authentication and authorization
- Enable audit logging for all cryptographic operations
- Run security scans regularly (`make security`)

❌ **DON'T:**
- Expose encryption keys in API responses or logs
- Allow unauthenticated access to encrypted data
- Disable security features in production

### For Contributors

✅ **DO:**
- Run `make security` before committing (bandit + safety checks)
- Use pre-commit hooks (`pre-commit install`)
- Follow secure coding guidelines (OWASP Top 10)
- Add security tests for new cryptographic features
- Document security implications in code comments

❌ **DON'T:**
- Introduce hardcoded credentials or keys
- Use insecure random number generators (`random.random()` - use `os.urandom()`)
- Bypass pre-commit hooks (`--no-verify`)

---

## Compliance & Regulatory Context

This project targets compliance with:

- **DORA (EU 2022/2554):** Digital Operational Resilience Act - Effective Jan 17, 2025
- **PCI DSS v4.0.1:** Future-dated requirements mandatory Mar 31, 2025
- **NYDFS 23 NYCRR Part 500:** Cybersecurity requirements for financial services
- **GDPR:** General Data Protection Regulation (Art. 25, 32)

Security considerations are documented in:
- `docs/COMPLIANCE_NOTES.md` - Regulatory mapping
- `docs/THREAT_MODEL.md` - Security analysis
- `docs/ARCHITECTURE.md` - Security architecture

---

## Security Testing

### Automated Security Checks

Our CI/CD pipeline includes:

- **Bandit:** Static security analysis for Python code
- **Safety:** Dependency vulnerability scanning
- **Ruff:** Security-focused linting rules
- **Pre-commit hooks:** Detect private keys, large files, merge conflicts

Run locally:
```bash
make security    # Full security scan
make lint        # Code quality + security checks
make ci          # Complete CI pipeline locally
```

### Manual Security Testing

For security researchers and auditors:

1. **Cryptographic Testing:**
   ```bash
   PYTHONPATH=src:$PYTHONPATH python -m pytest tests/test_blind_index.py -v
   PYTHONPATH=src:$PYTHONPATH python -m pytest tests/test_deterministic.py -v
   ```

2. **Leakage Analysis:**
   - See `docs/THREAT_MODEL.md` for explicit leakage profiles
   - Test tenant isolation: `tests/test_blind_index.py::test_tenant_isolation`

3. **Timing Attack Resistance:**
   - Constant-time verification: `BlindIndexSearch.verify_match()` uses `hmac.compare_digest()`

---

## External Security Audit

**Status:** Not completed

This repository has not completed an external cryptographic review,
penetration test, or compliance audit. Before any production use, engage an
independent security firm for:
- Comprehensive cryptographic review
- Penetration testing
- Compliance assessment for the specific regulatory scope

Interested security firms can contact: security@example.com

---

## Hall of Fame

We recognize security researchers who responsibly disclose vulnerabilities:

### 2025
- *No vulnerabilities reported yet* (v1.0.0 release)

### Future
- Your name here? Report a vulnerability!

---

## Contact

- **Security Email:** security@example.com
- **PGP Key:** https://keybase.io/encrypted_ir_team
- **GitHub Security:** https://github.com/MysterionRise/encrypted-information-retrieval/security
- **General Issues:** https://github.com/MysterionRise/encrypted-information-retrieval/issues (non-security only)

---

## Changelog

| Date       | Change |
|------------|--------|
| 2025-11-13 | Initial SECURITY.md created |
| 2026-07-07 | Repositioned as portfolio-grade prototype; clarified unaudited status |

---

**Last Updated:** 2026-07-07
**Next Review:** Before any production deployment or live cloud demo
