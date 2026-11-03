"""Shared test fixtures.

API tests build the app from explicit settings instead of the developer's environment, and
authenticate with short-lived dev JWTs signed by the app's own configured secret.

Databases: ``db_url`` is a fresh SQLite file per test. When ``POSTGRES_TEST_DATABASE_URL`` is
set, it is instead a PostgreSQL schema of its own per xdist worker (``w_gw0``, ``w_gw1``...),
migrated to head once per worker and truncated after every test, so the whole API suite runs on
PostgreSQL in parallel. ``postgres_url`` is that schema, or None.

Any response with status 500 fails the test unless it is marked ``allow_500``.
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable, Iterable, Iterator
from typing import Any

import jwt
import pytest
from alembic import command
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from encrypted_ir.api.main import create_app
from encrypted_ir.database import metadata
from encrypted_ir.logging import bind_correlation_id, reset_correlation_id
from encrypted_ir.migrations import alembic_config
from encrypted_ir.settings import EncryptedIRSettings

SettingsFactory = Callable[..., EncryptedIRSettings]
AppFactory = Callable[..., FastAPI]
TokenFactory = Callable[..., str]

TEST_JWT_SECRET = "test-only-dev-jwt-secret-0123456789abcdef"  # noqa: S105
TEST_DEV_API_KEY = "test-only-dev-api-key"


# -- databases ------------------------------------------------------------------------------


def _worker_schema() -> str:
    return f"w_{os.environ.get('PYTEST_XDIST_WORKER', 'main')}"


@pytest.fixture(scope="session")
def postgres_url() -> Iterator[str | None]:
    """This worker's migrated PostgreSQL schema, or None without POSTGRES_TEST_DATABASE_URL."""
    base = os.environ.get("POSTGRES_TEST_DATABASE_URL")
    if not base:
        yield None
        return
    schema = _worker_schema()
    admin = create_engine(base)
    try:
        with admin.begin() as conn:
            conn.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
            conn.execute(text(f'CREATE SCHEMA "{schema}"'))
    finally:
        admin.dispose()
    url = (
        make_url(base)
        .update_query_dict({"options": f"-csearch_path={schema}"})
        .render_as_string(hide_password=False)
    )
    command.upgrade(alembic_config(url), "head")
    yield url
    admin = create_engine(base)
    try:
        with admin.begin() as conn:
            conn.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
    finally:
        admin.dispose()


@pytest.fixture()
def require_postgres(postgres_url: str | None) -> Iterator[str]:
    """This worker's PostgreSQL schema URL, truncated afterwards; skips without PostgreSQL."""
    if postgres_url is None:
        pytest.skip("POSTGRES_TEST_DATABASE_URL is not configured")
    yield postgres_url
    _truncate_all(postgres_url)


def _truncate_all(url: str) -> None:
    tables = ", ".join(f'"{table.name}"' for table in metadata.sorted_tables)
    engine = create_engine(url)
    try:
        with engine.begin() as conn:
            conn.execute(text(f"TRUNCATE TABLE {tables} RESTART IDENTITY CASCADE"))
    finally:
        engine.dispose()


@pytest.fixture()
def db_url(tmp_path: Any, postgres_url: str | None) -> Iterator[str]:
    """A database for one test: a fresh SQLite file, or this worker's PostgreSQL schema."""
    if postgres_url is None:
        yield f"sqlite+pysqlite:///{tmp_path / 'test.db'}"
        return
    yield postgres_url
    _truncate_all(postgres_url)


# -- apps -----------------------------------------------------------------------------------


@pytest.fixture()
def master_key() -> bytes:
    """One master key per test, so every app a test builds can read the others' keys."""
    return os.urandom(32)


@pytest.fixture()
def settings_factory(db_url: str, master_key: bytes) -> SettingsFactory:
    """Return a factory for dev-mode settings on the test's database (``db_url``).

    Dev auth is on, with a test-only JWT secret and dev API key; ``/docs`` stays off unless a
    test passes ``enable_docs=True``. Tests that need an unmigrated database pass
    ``database_url="sqlite+pysqlite:///:memory:"``.
    """

    def _factory(**overrides: Any) -> EncryptedIRSettings:
        values: dict[str, Any] = {
            "environment": "dev",
            "database_url": db_url,
            "master_key": master_key,
            "generated_ephemeral_master_key": True,
            "auto_create_tables": True,
            "dev_auth_enabled": True,
            "jwt_secret": TEST_JWT_SECRET,
            "dev_api_key": TEST_DEV_API_KEY,
        }
        values.update(overrides)
        return EncryptedIRSettings(**values)

    return _factory


@pytest.fixture()
def app_factory(settings_factory: SettingsFactory) -> Iterator[AppFactory]:
    """Build apps from ``settings_factory(**overrides)`` or explicit settings; disposes their
    database engines after the test."""
    apps: list[FastAPI] = []

    def _build(settings: EncryptedIRSettings | None = None, **overrides: Any) -> FastAPI:
        built = create_app(settings if settings is not None else settings_factory(**overrides))
        apps.append(built)
        return built

    yield _build
    for built in apps:
        built.state.database_engine.dispose()


@pytest.fixture()
def app(app_factory: AppFactory) -> FastAPI:
    """Create a fresh app; metrics and rate limits live on ``app.state``, so nothing is shared."""
    return app_factory()


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    """Test client that returns 500 responses instead of raising."""
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture()
def make_token(app: FastAPI) -> TokenFactory:
    """Return a factory for dev HS256 tokens accepted by ``app``.

    Every token carries ``iat``, ``exp`` and ``roles``. Extra keyword arguments become claims,
    and a claim set to ``None`` is removed.
    """

    def _make(tenant_id: str | None, roles: Iterable[str], *, ttl: int = 300, **claims: Any) -> str:
        now = int(time.time())
        payload: dict[str, Any] = {
            "sub": f"{tenant_id}-user",
            "tenant_id": tenant_id,
            "roles": list(roles),
            "iat": now,
            "exp": now + ttl,
        }
        payload.update(claims)
        payload = {key: value for key, value in payload.items() if value is not None}
        return jwt.encode(payload, app.state.auth_config.jwt_secret, algorithm="HS256")

    return _make


def bearer(token: str) -> dict[str, str]:
    """Build an Authorization header for ``token``."""
    return {"Authorization": f"Bearer {token}"}


def metric(app: FastAPI, name: str, **labels: str) -> float:
    """Read one sample from ``app``'s Prometheus registry (0.0 if it was never recorded)."""
    value = app.state.metrics.registry.get_sample_value(name, labels)
    return 0.0 if value is None else float(value)


@pytest.fixture()
def auth_headers(make_token: TokenFactory) -> dict[str, str]:
    """Headers for tenant ``test-tenant-001`` with admin, write and read roles."""
    return bearer(make_token("test-tenant-001", ["admin", "write", "read"]))


@pytest.fixture()
def read_only_headers(make_token: TokenFactory) -> dict[str, str]:
    """Headers for tenant ``test-tenant-001`` with the read role only."""
    return bearer(make_token("test-tenant-001", ["read"]))


# -- guards ---------------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _fail_on_unexpected_500(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch):
    """Fail a test that receives a 500 from any TestClient, unless it is marked allow_500."""
    seen: list[str] = []
    original = TestClient.request

    def recording(self: TestClient, method: str, url: Any, *args: Any, **kwargs: Any) -> Any:
        response = original(self, method, url, *args, **kwargs)
        if response.status_code == 500:
            seen.append(f"{method} {url}")
        return response

    monkeypatch.setattr(TestClient, "request", recording)
    yield
    if seen and request.node.get_closest_marker("allow_500") is None:
        pytest.fail(
            f"Unexpected 500 response(s): {seen}. Mark the test allow_500 if they are intended.",
            pytrace=False,
        )


_RESTORED_LOGGERS = ("", "encrypted_ir", "encrypted_ir.api.access", "uvicorn.error")


@pytest.fixture(autouse=True)
def _restore_logging() -> Iterator[None]:
    """create_app configures logging globally; undo it, and the correlation ID, after a test."""
    saved = {
        name: (list(logger.handlers), logger.level, logger.propagate)
        for name in _RESTORED_LOGGERS
        for logger in [logging.getLogger(name)]
    }
    token = bind_correlation_id(None)
    yield
    reset_correlation_id(token)
    for name, (handlers, level, propagate) in saved.items():
        logger = logging.getLogger(name)
        logger.handlers[:] = handlers
        logger.setLevel(level)
        logger.propagate = propagate
