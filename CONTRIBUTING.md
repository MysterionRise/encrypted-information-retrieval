# Contributing

Thanks for looking at this project. It is a prototype for privacy-preserving retrieval in regulated
AI/RAG systems, maintained by one person. Small, well-evidenced pull requests are the easiest to
review.

## The one rule: claims need proof

A claim may live in this repository only if a test, a CI job or a dated evidence run backs it.
That applies to the README, `docs/`, docstrings and pull request descriptions. If you change
what the code does, update every place that describes it. If you cannot prove a property, describe
it as a goal or a limitation, not as a feature. [`docs/ROADMAP.md`](docs/ROADMAP.md) explains why
this matters here.

## Set up

Python 3.11 or 3.12.

```bash
python3.11 -m venv .venv
source .venv/bin/activate
make setup            # locked test environment + dev tools + pre-commit hooks
```

`make setup` installs `requirements-ci.txt` (the same locked environment CI uses) and
`requirements-dev.txt` (formatters, linters, pre-commit). For the optional TenSEAL and pqcrypto
research modules:

```bash
pip install -r requirements-research.txt
```

## Everyday commands

| Command | What it runs |
| --- | --- |
| `make test` | The full pytest suite, in parallel (`pytest -n auto`). With `POSTGRES_TEST_DATABASE_URL` set it runs on PostgreSQL; otherwise on SQLite, and Postgres-only tests skip. |
| `make test-coverage` | The suite with coverage. CI fails below the floor set in `.github/workflows/ci.yml`. |
| `make format` | black, then `ruff check --fix`. |
| `make lint` | ruff, bandit and mypy, with the same arguments as CI. |
| `make security` | bandit and pip-audit, as in CI. |
| `make pre-commit-check` | black check, ruff and a quick test run. |
| `make bench` | pytest-benchmark timings for `benchmarks/`, compared with `benchmarks/baseline.json` by `scripts/compare_benchmarks.py`. |
| `docker compose up --build`, then `./scripts/compose_smoke.sh` | The Compose persistence smoke test that CI runs. |

CI pins exact versions of black, ruff, mypy and bandit in the `env` block of
`.github/workflows/ci.yml`. `.pre-commit-config.yaml` mirrors those pins. Change both together.

## Tests

- Every behaviour change comes with a test that fails without it.
- Do not skip, disable or loosen a test to make CI green. If a test is wrong, fix it and say why in
  the pull request.
- Security properties get adversarial tests: wrong key, other tenant, tampered ciphertext,
  expired or malformed credentials.
- The coverage floor only goes up. Raise it in `ci.yml` when coverage improves.
- Build apps with the `app_factory` fixture (or `app`), not `create_app` directly: it uses the
  test's database and disposes the engine afterwards. `db_url` is a fresh SQLite file per test;
  with `POSTGRES_TEST_DATABASE_URL` set, it is a PostgreSQL schema of the xdist worker's own
  (`w_gw0`, ...), migrated once and truncated after every test. Use `require_postgres` for tests
  that only make sense on PostgreSQL, never the environment variable directly.
- A 500 response fails the test that receives it. Mark a test `@pytest.mark.allow_500` only when
  the 500 is the behaviour under test.
- `tests/test_route_matrix.py` lists every `/v1` route with its 401, 403 and cross-tenant cases,
  and fails when a new route has none. Add the route there.
- No wall-clock assertions: synchronize with events, inject clocks, and keep timeouts only as
  deadlock guards.
- Benchmarks live in `benchmarks/`, outside `testpaths`, so the suite never calibrates them. The
  benchmarks job runs on master only and is informational; it fails on a median more than 3x the
  committed baseline. Refresh the baseline with
  `python scripts/compare_benchmarks.py <report.json> --update` when a slowdown is expected.

## Dependencies

- Runtime dependencies live in `pyproject.toml` (`[project.dependencies]`) and are mirrored in
  `requirements.txt`.
- `requirements-docker.txt`, the Docker image's lock, is generated from `pyproject.toml` with the
  `aws` extra and pins every package by hash. Regenerate it with Python 3.11 after changing the
  dependencies:

  ```bash
  pip-compile --extra aws --generate-hashes --strip-extras --allow-unsafe \
    --output-file requirements-docker.txt pyproject.toml
  ```

- `requirements-ci.txt` is generated. Do not edit it by hand. After changing
  `requirements-ci.in` or `requirements.txt`, regenerate it with Python 3.11:

  ```bash
  pip install pip-tools
  pip-compile --strip-extras --output-file requirements-ci.txt requirements-ci.in
  ```

- Dependabot opens weekly update PRs for pip, GitHub Actions and the Dockerfile's base image,
  which is pinned by digest.

## Database migrations

Alembic scripts ship inside the package at `src/encrypted_ir/alembic_migrations/`, so installed
wheels can run them. From a checkout:

```bash
DATABASE_URL=sqlite+pysqlite:///local.db alembic upgrade head
alembic revision -m "describe the change"   # then edit the new file under versions/
```

`alembic.ini` names no database: the `alembic` CLI migrates the one in `DATABASE_URL`. Code that
builds its own config (`encrypted_ir.migrations.alembic_config(url)`) migrates exactly that URL,
whatever `DATABASE_URL` says. Without `alembic.ini`, for example in the Docker image, run
`python -m encrypted_ir.migrations upgrade head` (also `downgrade REV` and `current`).

## Documentation and decisions

- Start from [`docs/README.md`](docs/README.md), which maps current docs versus reference material.
- If a change affects what the system leaks, update
  [`docs/LEAKAGE_AND_ENDPOINTS.md`](docs/LEAKAGE_AND_ENDPOINTS.md).
- Record architectural decisions in [`docs/DECISIONS.md`](docs/DECISIONS.md): copy the template at
  the end, take the next ADR number, and set the status honestly (Proposed, Accepted, Superseded).
- Add a line under `## [Unreleased]` in [`CHANGELOG.md`](CHANGELOG.md) for user-visible changes.

## Pull requests

- Keep each PR to one concern, and link its issue with `Closes #NN` or `Part of #NN`.
- Commit messages use a short prefix, as in the history: `feat:`, `fix:`, `docs:`, `ci:`, `deps:`,
  `release:`.
- The PR template's checklist is the definition of done.

## Security

Report vulnerabilities privately as described in [`SECURITY.md`](SECURITY.md), never in a public
issue or pull request.
