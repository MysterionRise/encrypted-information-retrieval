# Documentation Map

This repo contains both current portfolio evidence and older planning/reference material. Use this map to avoid treating target-state docs as current implementation claims.

## Read First

| Document | Purpose |
| --- | --- |
| [../README.md](../README.md) | Concise project entry point, demo path, boundaries, and commands. |
| [PORTFOLIO_EVIDENCE.md](PORTFOLIO_EVIDENCE.md) | Current portfolio evidence and verification summary. |
| [CURRENT_STATUS.md](CURRENT_STATUS.md) | Current implementation status, quality commands, known limitations, and production gaps. |
| [PORTFOLIO_CASE_STUDY.md](PORTFOLIO_CASE_STUDY.md) | CTO-facing case study for the regulated AI/RAG retrieval prototype. |
| [CTO_DEMO_SCRIPT.md](CTO_DEMO_SCRIPT.md) | Five-minute demo script for CTO review. |
| [LEAKAGE_AND_ENDPOINTS.md](LEAKAGE_AND_ENDPOINTS.md) | Endpoint-to-leakage map and production boundary. |
| [DOCKER_COMPOSE_SMOKE_TEST.md](DOCKER_COMPOSE_SMOKE_TEST.md) | Local restart-persistence smoke test. |

## Reference Material

| Document | How to read it |
| --- | --- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Architecture reference and target hardening shape. Some diagrams include production components not deployed by default. |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Threat-model and leakage-budget reference. Some mitigations are target-state controls. |
| [DECISIONS.md](DECISIONS.md) | ADR-style design rationale. Some decisions describe intended production architecture. |
| [COMPLIANCE_NOTES.md](COMPLIANCE_NOTES.md) | Regulatory control mapping for discussion. It is not an audit report, legal opinion, or compliance certification. |
| [migration/OPE_TO_ORE.md](migration/OPE_TO_ORE.md) | Migration guidance and rationale for preferring ORE over OPE. |

## Historical Planning Material

| Document | Status |
| --- | --- |
| [GAP_ANALYSIS.md](GAP_ANALYSIS.md) | Historical gap analysis with stale counts, timelines, and compliance percentages. |
| [GITHUB_ISSUES.md](GITHUB_ISSUES.md) | Backlog draft, not the authoritative GitHub issue tracker. |
| [LLM_SYSTEM_ANALYSIS.md](LLM_SYSTEM_ANALYSIS.md) | Long-form analysis generated for LLM context; useful but not the current status ledger. |
| [MVP_COMPLETION_SUMMARY.md](MVP_COMPLETION_SUMMARY.md) | Historical milestone summary. |

## Accuracy Rule

When docs disagree, prefer this order:

1. executable code and tests,
2. `docs/PORTFOLIO_EVIDENCE.md`,
3. `README.md`,
4. current reference docs,
5. historical planning docs.
