# Compliance & Regulatory Alignment

> **Portfolio status note (July 7, 2026):** This is historical planning and
> regulatory-mapping material, not evidence of certification. Current
> implementation evidence lives in `README.md`, `docs/PORTFOLIO_EVIDENCE.md`,
> `docs/LEAKAGE_AND_ENDPOINTS.md`, and `docs/CTO_DEMO_SCRIPT.md`. Claims about
> audit readiness, CloudTrail, immutable logs, FIPS-backed KMS, or certification
> should be read as roadmap targets unless explicitly backed by current evidence.

**Version**: 1.0
**Last Updated**: January 2025
**Scope**: Encrypted IR System for Financial Services

## Table of Contents

1. [Overview](#overview)
2. [DORA (EU Digital Operational Resilience Act)](#dora-eu-digital-operational-resilience-act)
3. [NYDFS 23 NYCRR Part 500](#nydfs-23-nycrr-part-500)
4. [PCI DSS v4.0/4.0.1](#pci-dss-v40401)
5. [GDPR (General Data Protection Regulation)](#gdpr-general-data-protection-regulation)
6. [SOX (Sarbanes-Oxley Act)](#sox-sarbanes-oxley-act)
7. [NIST Cybersecurity Framework](#nist-cybersecurity-framework)
8. [Implementation Checklist](#implementation-checklist)
9. [Audit Readiness](#audit-readiness)

---

## Overview

This document maps the Encrypted IR system's security controls to key financial services regulations **effective January 2025**. It provides evidence for auditors, gap analysis, and compensating controls where needed.

**Key Dates:**
- ✅ **DORA**: Applicable since **January 17, 2025** ([EIOPA Regulation 2022/2554](https://www.eiopa.europa.eu))
- ✅ **PCI DSS v4.0.1**: Future-dated requirements **mandatory March 31, 2025**
- ✅ **NYDFS Part 500**: Nov 1, 2023 amendments in effect; 2024-2025 transition windows active
- ✅ **GDPR**: In force since May 2018; ongoing enforcement

**Regulatory Posture:**
- ✅ **Confidentiality**: AES-256 encryption at rest and in transit
- ✅ **Integrity**: AEAD tags, audit logs with cryptographic hashes
- ✅ **Auditability**: Immutable audit trail of all key operations
- ⚠️ **Incident Response**: Automated breach notification (roadmapped P1)

---

## DORA (EU Digital Operational Resilience Act)

**Regulation**: [EU 2022/2554](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32022R2554)
**Applicable Since**: January 17, 2025
**Scope**: EU financial entities (banks, insurers, investment firms, crypto-asset service providers)

### Key Requirements & Implementation

#### Article 6: Governance and Organisation

| Requirement | Implementation | Evidence | Gap |
|-------------|----------------|----------|-----|
| **6.1**: ICT risk management framework | ✅ Threat model (THREAT_MODEL.md), risk register | Documented threat model, leakage budget | None |
| **6.4**: Roles and responsibilities | ✅ CODEOWNERS file, access control matrix | IAM policies, RBAC | None |
| **6.8**: ICT risk appetite | ✅ Leakage budget by feature, residual risk acceptance | THREAT_MODEL.md §6 | None |

#### Article 9: ICT Risk Management Framework

| Requirement | Implementation | Evidence | Gap |
|-------------|----------------|----------|-----|
| **9.1(a)**: Identification of ICT risk | ✅ Threat modeling, attack tree analysis | THREAT_MODEL.md §5 | None |
| **9.1(b)**: Protection & prevention mechanisms | ✅ AES-256, AEAD, key rotation, access controls | Crypto implementation, KMS policies | None |
| **9.1(c)**: Detection mechanisms | ✅ Audit logging, anomaly detection | CloudTrail integration, rate limiting | ⚠️ Real-time alerting (P1) |
| **9.1(d)**: Response & recovery | ⚠️ Crypto-shredding, key rotation procedures | Documented runbooks | ⚠️ Automated incident response (P1) |
| **9.1(e)**: Learning and evolving | ✅ Post-incident reviews, crypto-agility | ADR log (DECISIONS.md) | None |

#### Article 10: Detection and Prevention of ICT Incidents

| Requirement | Implementation | Evidence | Gap |
|-------------|----------------|----------|-----|
| **10.1**: Early warning indicators | ✅ Rate limiting, anomaly detection on key access | Monitoring dashboards | ⚠️ ML-based anomaly detection (P2) |
| **10.2**: Response procedures | ⚠️ Emergency key rotation, crypto-shredding | Runbooks | ⚠️ Automated response (P1) |

#### Article 14: Testing of ICT Business Continuity Plans

| Requirement | Implementation | Evidence | Gap |
|-------------|----------------|----------|-----|
| **14.1**: Annual BCP testing | ⚠️ Key recovery drills, failover tests | Test reports | ⚠️ Automated DR testing (P1) |
| **14.4**: TLPT (Threat-Led Penetration Testing) | ⚠️ Planned for 2025-Q2 | Pen test scope | ⚠️ External TLPT (2025-Q2) |

#### Article 28: ICT Third-Party Risk Management

| Requirement | Implementation | Evidence | Gap |
|-------------|----------------|----------|-----|
| **28.1**: Due diligence on KMS/HSM providers | ✅ AWS KMS (FIPS 140-3 Level 3), vendor risk assessment | Vendor certifications | None |
| **28.6**: Audit rights for critical services | ✅ CloudTrail logs; SOC 2 Type II reports | Audit reports | None |

**DORA Compliance Summary:**
- ✅ **Core controls**: Encryption, key management, audit logging
- ⚠️ **Gaps**: Automated incident response, real-time alerting (P1 roadmap)
- 🔄 **Action Items**: TLPT by 2025-Q2, DR automation by 2025-Q3

---

## NYDFS 23 NYCRR Part 500

**Regulation**: [NY Dept. of Financial Services Cybersecurity Requirements](https://www.dfs.ny.gov/industry_guidance/cybersecurity)
**Amendments**: November 1, 2023 (with transition periods through 2025)
**Scope**: NY-licensed financial institutions

### Key Requirements & Implementation

#### § 500.02: Cybersecurity Program

| Requirement | Implementation | Evidence | Gap |
|-------------|----------------|----------|-----|
| **Encryption of nonpublic info** | ✅ AES-256 at rest (AES-SIV, AES-GCM) and in transit (TLS 1.3) | Crypto implementation | None |
| **Multi-factor authentication** | ✅ MFA required for KMS key operations | IAM policies | None |
| **Risk assessment** | ✅ Annual threat model review | THREAT_MODEL.md | None |

#### § 500.15: Encryption of Nonpublic Information

| Requirement | Implementation | Evidence | Gap |
|-------------|----------------|----------|-----|
| **15(a)**: Encrypt nonpublic info at rest | ✅ AES-256-GCM/SIV for all PII, financial data | Ciphertext format docs | None |
| **15(b)**: Encrypt in transit | ✅ TLS 1.3 with strong cipher suites | TLS config, cert chain | None |
| **15(c)**: Compensating controls | ✅ TEE option (AWS Nitro Enclaves) for high-sensitivity | Enclave attestation docs | ⚠️ Full TEE rollout (P1) |

#### § 500.12: Multi-Factor Authentication

| Requirement | Implementation | Evidence | Gap |
|-------------|----------------|----------|-----|
| **MFA for privileged accounts** | ✅ Required for KMS Decrypt/GenerateDataKey | IAM condition keys | None |
| **MFA for remote access** | ✅ SSO with TOTP/WebAuthn | Identity provider config | None |

#### § 500.17: Incident Response Plan

| Requirement | Implementation | Evidence | Gap |
|-------------|----------------|----------|-----|
| **IR plan with procedures** | ⚠️ Crypto-shredding, key rotation runbooks | Documentation | ⚠️ 72-hour breach notification automation (P1) |
| **Annual testing** | ⚠️ Tabletop exercises | Test reports | ⚠️ Automated IR testing (P1) |

#### § 500.23: Certification of Compliance (Annual Filing)

| Requirement | Implementation | Evidence | Gap |
|-------------|----------------|----------|-----|
| **Board-level certification** | ⚠️ Compliance report generation | Automated reports | ⚠️ Exec dashboard (P1) |
| **Due by April 15 annually** | ⚠️ Checklist for 2025 filing | Compliance matrix | ⚠️ Pre-audit validation (2025-Q1) |

**NYDFS Compliance Summary:**
- ✅ **Strong encryption**: Meets § 500.15 requirements
- ✅ **MFA**: Enforced for privileged operations
- ⚠️ **Gaps**: Incident response automation, annual testing cadence (P1)
- 🔄 **Action Items**: Certify compliance by April 15, 2025

---

## PCI DSS v4.0/4.0.1

**Standard**: [Payment Card Industry Data Security Standard v4.0.1](https://www.pcisecuritystandards.org)
**Future-Dated Deadline**: March 31, 2025 (all future-dated requirements become mandatory)
**Scope**: Cardholder data environments (CDE)

### Key Requirements & Implementation

#### Requirement 3: Protect Stored Cardholder Data

| Requirement | Implementation | Evidence | Gap |
|-------------|----------------|----------|-----|
| **3.5.1**: Encrypt PAN with strong crypto | ✅ AES-256-SIV for deterministic PAN lookup; AES-256-GCM for storage | Crypto spec, test vectors | None |
| **3.5.1.2**: Key strength ≥112 bits | ✅ 256-bit keys (AES-256) | Key generation code | None |
| **3.5.1.3**: Cryptoperiods defined | ✅ DEK rotation every 90 days | Rotation policy doc | None |
| **3.6.1**: Protect crypto keys | ✅ KEKs in AWS KMS (FIPS 140-3 Level 3) | KMS audit logs | None |
| **3.6.1.1**: Key access restricted | ✅ IAM policies, MFA, attestation | Access control matrix | None |
| **3.6.1.2**: Keys stored encrypted | ✅ Envelope encryption (DEK encrypted by KEK) | Architecture diagram | None |

#### Requirement 3.6.4: Cryptographic Key Changes (Future-Dated)

| Requirement | Implementation | Evidence | Gap |
|-------------|----------------|----------|-----|
| **3.6.4.1**: Key rotation procedures | ✅ Automated DEK re-wrap on rotation | Rotation scripts | None |
| **3.6.4.2**: Retired keys protected | ✅ Archived keys encrypted; access logged | Key archive policy | None |

#### Requirement 4: Protect Cardholder Data in Transit

| Requirement | Implementation | Evidence | Gap |
|-------------|----------------|----------|-----|
| **4.2.1**: TLS 1.2+ with strong ciphers | ✅ TLS 1.3 enforced; cipher suites: TLS_AES_256_GCM_SHA384 | TLS config | None |
| **4.2.1.1**: Certificate validation | ✅ Certificate pinning, chain validation | Code review | None |

#### Requirement 10: Log and Monitor All Access

| Requirement | Implementation | Evidence | Gap |
|-------------|----------------|----------|-----|
| **10.2.2**: Log all KMS operations | ✅ CloudTrail integration; immutable logs | Sample log entries | None |
| **10.3**: Audit log details (user, timestamp, event) | ✅ Structured JSON logs with (user_id, timestamp, key_id, operation) | Log schema | None |
| **10.4.1.1**: Critical logs reviewed daily | ⚠️ Anomaly detection alerts | Monitoring dashboard | ⚠️ Real-time alerting (P1) |

#### Requirement 12.3: Cryptographic Architecture (Future-Dated)

| Requirement | Implementation | Evidence | Gap |
|-------------|----------------|----------|-----|
| **12.3.4**: Document crypto architecture | ✅ ARCHITECTURE.md, DECISIONS.md | This repo | None |
| **12.3.4.1**: Key management procedures | ✅ KMS policy, rotation schedule | Key management runbooks | None |

**PCI DSS Compliance Summary:**
- ✅ **Encryption**: AES-256 with FIPS-validated HSMs
- ✅ **Key management**: Envelope encryption, rotation, audit logging
- ⚠️ **Gaps**: Real-time log monitoring (P1); future-dated requirements met by 2025-03-31
- 🔄 **Action Items**: QSA audit by 2025-Q2

---

## GDPR (General Data Protection Regulation)

**Regulation**: [EU 2016/679](https://gdpr-info.eu)
**Enforcement**: Active since May 25, 2018
**Scope**: EU personal data processing

### Key Principles & Implementation

#### Article 5: Principles Relating to Processing

| Principle | Implementation | Evidence | Gap |
|-----------|----------------|----------|-----|
| **Data minimization** | ✅ Encrypted fields only; blind indexes vs. full ciphertexts | Design docs | None |
| **Storage limitation** | ✅ Crypto-shredding for RTBF (Right to be Forgotten) | Deletion procedures | None |
| **Integrity & confidentiality** | ✅ AES-256, AEAD, audit logs | THREAT_MODEL.md | None |

#### Article 25: Data Protection by Design and by Default

| Requirement | Implementation | Evidence | Gap |
|-------------|----------------|----------|-----|
| **Privacy by design** | ✅ Encrypted-first architecture; blind indexes | Architecture diagram | None |
| **Pseudonymization** | ✅ HMAC-based indexes; no direct identifiers | Blind index implementation | None |

#### Article 32: Security of Processing

| Requirement | Implementation | Evidence | Gap |
|-------------|----------------|----------|-----|
| **32(1)(a)**: Pseudonymization & encryption | ✅ AES-256, blind indexes, SSE | Crypto spec | None |
| **32(1)(b)**: Confidentiality & integrity | ✅ AEAD, TLS 1.3, audit logs | Security controls | None |
| **32(1)(c)**: Resilience & availability | ⚠️ Multi-AZ KMS, DEK replication | DR plan | ⚠️ Automated DR (P1) |
| **32(1)(d)**: Regular testing | ✅ 112-test suite, pen testing planned | CI/CD pipeline | ⚠️ Annual pen test (2025-Q2) |

#### Article 33/34: Breach Notification (72 hours)

| Requirement | Implementation | Evidence | Gap |
|-------------|----------------|----------|-----|
| **Notify DPA within 72 hours** | ⚠️ Breach detection + crypto-shredding | Runbooks | ⚠️ Automated notification (P1) |
| **Notify data subjects** | ⚠️ Templated notifications | Templates | ⚠️ Automation (P1) |

#### Article 35: Data Protection Impact Assessment (DPIA)

| Requirement | Implementation | Evidence | Gap |
|-------------|----------------|----------|-----|
| **DPIA for high-risk processing** | ✅ THREAT_MODEL.md serves as DPIA foundation | Risk assessment | None |
| **Consultation with DPO** | ⚠️ Legal review required | Legal sign-off | ⚠️ DPO consultation (pre-launch) |

**GDPR Compliance Summary:**
- ✅ **Art. 32 Security**: State-of-the-art encryption, audit logs
- ✅ **Art. 25 Privacy by Design**: Pseudonymization, data minimization
- ⚠️ **Gaps**: Automated breach notification (P1), DPIA legal review
- 🔄 **Action Items**: DPO consultation, breach simulation by 2025-Q2

---

## SOX (Sarbanes-Oxley Act)

**Law**: [Sarbanes-Oxley Act of 2002](https://www.sec.gov/about/laws/soa2002.pdf)
**Scope**: Publicly traded companies (financial reporting integrity)

### Key Requirements & Implementation

#### Section 302: Corporate Responsibility for Financial Reports

| Requirement | Implementation | Evidence | Gap |
|-------------|----------------|----------|-----|
| **Integrity of financial data** | ✅ HMAC-based integrity checks; AEAD tags | Crypto design | None |
| **Audit trail of changes** | ✅ Immutable logs (CloudTrail, KMS audit) | Log retention policy | None |

#### Section 404: Management Assessment of Internal Controls

| Requirement | Implementation | Evidence | Gap |
|-------------|----------------|----------|-----|
| **IT General Controls (ITGC)** | ✅ Access controls, change management, audit logging | ITGC matrix | None |
| **Segregation of duties** | ✅ Separate keys for encrypt vs. decrypt (where applicable) | IAM policies | None |

**SOX Compliance Summary:**
- ✅ **Data integrity**: Cryptographic MACs, audit trails
- ✅ **Access controls**: RBAC, MFA, audit logging
- **No gaps** for encrypted IR use cases

---

## NIST Cybersecurity Framework

**Framework**: [NIST CSF 2.0](https://www.nist.gov/cyberframework) (updated 2024)
**Adoption**: Voluntary; widely used in FS sector

### Core Functions Mapping

| Function | Implementation | Evidence |
|----------|----------------|----------|
| **Identify** | ✅ Asset inventory (keys, data types), risk assessment | THREAT_MODEL.md |
| **Protect** | ✅ AES-256, access controls, MFA, key rotation | Crypto implementation, IAM policies |
| **Detect** | ✅ Audit logging, anomaly detection | Monitoring dashboards |
| **Respond** | ⚠️ IR runbooks, crypto-shredding | Documented procedures; ⚠️ automation (P1) |
| **Recover** | ⚠️ Key recovery, DR plan | Recovery procedures; ⚠️ testing (P1) |

**NIST CSF Alignment:**
- ✅ Strong coverage of Identify/Protect/Detect
- ⚠️ Respond/Recover need automation (P1)

---

## Implementation Checklist

### Pre-Production Checklist (MVP)

- [x] **Encryption at rest**: AES-256 (AES-SIV, AES-GCM)
- [x] **Encryption in transit**: TLS 1.3
- [x] **Key management**: Envelope encryption, HSM-backed KEKs
- [x] **Audit logging**: CloudTrail integration for all KMS ops
- [x] **Access controls**: IAM policies, MFA for sensitive ops
- [x] **Threat model**: Documented leakage profile and residual risks
- [x] **Compliance mapping**: DORA, NYDFS, PCI, GDPR, SOX
- [ ] **Pen testing**: External TLPT (Q2 2025)
- [ ] **DPIA/legal review**: DPO consultation (pre-launch)
- [ ] **Incident response**: Automated breach notification (P1)

### Post-Launch Monitoring (Ongoing)

- [x] **Key rotation**: Automated DEK rotation (90 days)
- [x] **Audit log review**: Daily anomaly detection
- [ ] **Annual pen test**: Schedule for Q2 2025
- [ ] **DORA TLPT**: Q2 2025
- [ ] **PCI QSA audit**: Q2 2025 (for card data environments)
- [ ] **NYDFS cert**: File by April 15, 2025

---

## Audit Readiness

### Evidence Artifacts for Auditors

| Artifact | Location | Purpose |
|----------|----------|---------|
| **Threat Model** | `/docs/THREAT_MODEL.md` | Risk assessment, leakage budget |
| **Compliance Notes** | `/docs/COMPLIANCE_NOTES.md` (this doc) | Regulatory mapping |
| **Architecture Diagrams** | `/docs/ARCHITECTURE.md` | System design, data flows |
| **Crypto Decisions Log** | `/docs/DECISIONS.md` | ADR for algorithm choices |
| **Key Management Policy** | Key manager code + IAM policies | Rotation, access controls |
| **Audit Logs Sample** | CloudTrail exports | Decrypt/Encrypt operations |
| **Test Reports** | CI/CD pipeline, test suite (112 tests) | Security validation |
| **Pen Test Report** | Q2 2025 deliverable | External assessment |
| **Vendor Certifications** | AWS KMS SOC 2 Type II, FIPS 140-3 | Third-party assurance |

### Common Auditor Questions & Answers

**Q1: "How do you protect encryption keys?"**
**A**: Envelope encryption with KEKs stored in AWS KMS (FIPS 140-3 Level 3 HSM). DEKs encrypted at rest; keys never leave HSM plaintext. Access requires IAM policy + MFA. Audit trail via CloudTrail.

**Q2: "What is your key rotation policy?"**
**A**: DEKs rotate every 90 days (automated re-wrap). KEKs rotate annually. Emergency rotation procedures documented for breach scenarios.

**Q3: "How do you ensure data confidentiality?"**
**A**: AES-256 encryption at rest (AES-SIV for deterministic, AES-GCM for standard). TLS 1.3 in transit. All algorithms FIPS-approved.

**Q4: "What leakage does your searchable encryption have?"**
**A**: SSE leaks query repetition and access patterns. Mitigated by forward privacy (updates unlinkable to past queries) and optional PIR mode. Detailed leakage analysis in THREAT_MODEL.md.

**Q5: "How do you respond to a data breach?"**
**A**: Crypto-shredding (delete keys → data unrecoverable). Emergency key rotation. Breach notification procedures (GDPR 72-hour timeline). Documented in IR runbooks; automation planned for P1.

---

## Gap Analysis & Roadmap

### Critical Gaps (P0 - Before Production)

1. ✅ **OPE → ORE upgrade**: Reduce range query leakage
2. ⚠️ **Legal/DPO review**: GDPR DPIA consultation
3. ⚠️ **External pen test**: TLPT for DORA, general pen test for PCI/NYDFS

### High-Priority Gaps (P1 - Post-Launch)

4. ⚠️ **Automated incident response**: 72-hour breach notification
5. ⚠️ **Real-time alerting**: CloudWatch alarms for anomalous key access
6. ⚠️ **DR automation**: Quarterly DR drills with automated failover

### Medium-Priority Gaps (P2 - Future Enhancements)

7. ⚠️ **Immutable audit ledger**: QLDB for tamper-proof logs
8. ⚠️ **PQC hybrid mode**: Kyber + X25519 for quantum resistance
9. ⚠️ **TEE full rollout**: Nitro Enclaves for all sensitive decryptions

---

## Regulatory Change Monitoring

**Process**: Security team reviews regulatory updates quarterly (Q1/Q4/Q7/Q10).

**Key Sources:**
- PCI SSC: https://www.pcisecuritystandards.org
- NYDFS: https://www.dfs.ny.gov
- EIOPA (DORA): https://www.eiopa.europa.eu
- NIST: https://csrc.nist.gov

**Last Review**: 2025-01-11
**Next Review**: 2025-04-01

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-01-11 | Compliance Team | Initial compliance mapping |

---

## Contact & Escalation

- **Compliance Questions**: compliance@company.com
- **Security Incidents**: security-incident@company.com (24/7)
- **DPO Consultation**: dpo@company.com
- **External Auditors**: audit-coordination@company.com

---

**Classification**: Internal Use Only
**Review Cycle**: Quarterly
