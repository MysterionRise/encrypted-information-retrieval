# Documentation Map

Every document outside `archive/` is meant to be accurate for the current code. If you find a
statement the code does not back, that is a bug: please open an issue.

**Core versus research.** The durable API path and the standard constructions it uses are in the
`encrypted_ir` package. Unaudited prototypes (ORE, FF1, CKKS, post-quantum, differential privacy,
forward-private SSE, the use-case demos) are in `encrypted_ir.research`, which warns on import and is
never imported by the core package or the API. THREAT_MODEL.md covers both, and says which is which.

## Read first

| Document | Purpose |
| --- | --- |
| [../README.md](../README.md) | Entry point: what is real, demo paths, boundaries and commands. |
| [PORTFOLIO_EVIDENCE.md](PORTFOLIO_EVIDENCE.md) | The dated evidence run, current status, known limitations, and how to reproduce. |
| [ROADMAP.md](ROADMAP.md) | Phased roadmap (v0.9.0, then v0.10.0, then v1.0.0), the findings behind it, and links to the GitHub issues. |
| [THREAT_MODEL.md](THREAT_MODEL.md) | What the code protects, what it leaks, and each known gap with its tracking issue. |
| [LEAKAGE_AND_ENDPOINTS.md](LEAKAGE_AND_ENDPOINTS.md) | Per-endpoint leakage map and production boundary. |
| [CTO_DEMO_SCRIPT.md](CTO_DEMO_SCRIPT.md) | Five-minute Docker Compose demo. It doubles as the persistence smoke test. |

## Reference

| Document | How to read it |
| --- | --- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | The "As built" section describes the current code. The "Target state" section is the original 2025 design, kept as reference and clearly labelled. |
| [DECISIONS.md](DECISIONS.md) | Architecture decision records. ADR-001 to ADR-010 are 2025 target decisions with corrected statuses. ADR-011 to ADR-018 record decisions reflected in the code or accepted for the roadmap. |
| [OIDC_DEPLOYMENT.md](OIDC_DEPLOYMENT.md) | What the API requires of a token, the local Keycloak run in production mode, and claim mappings for Cognito, Auth0, Okta and Entra ID. |
| [KMS_DEPLOYMENT.md](KMS_DEPLOYMENT.md) | The AWS KMS key path: running it locally against an emulator, the production steps, the IAM policies in [iam/](iam/), and CloudTrail. |
| [PORTFOLIO_CASE_STUDY.md](PORTFOLIO_CASE_STUDY.md) | Short narrative of the problem, the approach and the leakage trade-offs. |

## Archive

[archive/](archive/README.md) holds 2025 planning and target-state material: the gap analysis,
the backlog draft, the compliance notes, the OPE-to-ORE guide, and other analyses. Nothing there is
a current claim.

## Accuracy rule

When documents disagree, prefer this order:

1. executable code and tests,
2. CI results,
3. `docs/PORTFOLIO_EVIDENCE.md`,
4. `README.md` and the documents under "Read first",
5. reference documents,
6. the archive.

Run `make docs-check` to verify that every relative link in the maintained Markdown files
resolves.
