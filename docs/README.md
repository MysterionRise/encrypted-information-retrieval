# Documentation Map

Every document outside `archive/` is meant to be accurate for the current code. If you find a
statement the code does not back, that is a bug: please open an issue.

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
| [DECISIONS.md](DECISIONS.md) | Architecture decision records. ADR-001 to ADR-010 are 2025 target decisions with corrected statuses. ADR-011 to ADR-016 record decisions reflected in the code or accepted for the roadmap. |
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
