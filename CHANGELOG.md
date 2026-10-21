# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). While the version is
below 1.0.0, minor versions may contain breaking changes.

The roadmap that drives these versions is in [docs/ROADMAP.md](docs/ROADMAP.md):
`0.9.0` closes Phase 0 (issue #26), `0.10.0` closes Phase 1 (issue #27), and
`1.0.0` closes Phase 2 (issue #28).

## [Unreleased]

### Removed

- The demo API routes `POST /v1/encrypt`, `POST /v1/decrypt`, `POST /v1/search/equality`,
  `POST /v1/search/range`, `POST /v1/search/keyword`, `GET /v1/keys` and `POST /v1/keys/rotate`
  (#36). They held random per-process keys in module globals, so their data did not survive a
  restart, differed between workers and shared nothing with the stored documents. The API now
  serves only the durable document routes plus `/health`, `/ready` and `/metrics`.
  Library-level blind-index and ORE demos remain in `examples/portfolio_demo.py`.
- The in-memory API-key registry (`register_api_key`, `clear_api_keys`), which only tests used,
  and the request and response models of the removed routes.

### Changed

- The package version is now `0.9.0` with the classifier `Development Status :: 3 - Alpha`,
  matching the project's prototype status. The earlier `1.0.0` string was never tagged or released.
- The version has one source, `encrypted_ir.__version__`. `pyproject.toml`, the FastAPI app,
  `/health`, `make info` and the tests read it from there.
- The build requires `setuptools>=77`, which the SPDX string `license = "MIT"` needs.
- GitHub Actions bumped by Dependabot: `actions/checkout` v6, `actions/setup-python` v6,
  `actions/upload-artifact` v7, `codecov/codecov-action` v6.
- Development dependency floors bumped by Dependabot: ipython, isort, myst-parser,
  pytest-timeout, sphinx, types-setuptools.

### Added

- `CHANGELOG.md`.
- A release workflow (`.github/workflows/release.yml`). Pushing a `v*` tag checks that the tag
  matches the package version, builds the sdist and wheel, runs `twine check`, generates a
  CycloneDX SBOM, and publishes a GitHub Release whose notes are this file's section for that
  version.

## History before 0.9.0

No version was tagged or released before 0.9.0. Earlier work is in the git history and in
`docs/PORTFOLIO_EVIDENCE.md`.
