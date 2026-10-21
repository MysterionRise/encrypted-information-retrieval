"""Shared test fixtures.

API tests build the app from explicit settings instead of the developer's environment, and
authenticate with short-lived dev JWTs signed by the app's own configured secret.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable, Iterable
from typing import Any

import jwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from encrypted_ir.api.dependencies.rate_limiter import RateLimiter, set_rate_limiter
from encrypted_ir.api.main import create_app
from encrypted_ir.api.routes.admin import reset_metrics
from encrypted_ir.settings import EncryptedIRSettings

SettingsFactory = Callable[..., EncryptedIRSettings]
TokenFactory = Callable[..., str]

TEST_JWT_SECRET = "test-only-dev-jwt-secret-0123456789abcdef"  # noqa: S105
TEST_DEV_API_KEY = "test-only-dev-api-key"


@pytest.fixture()
def settings_factory() -> SettingsFactory:
    """Return a factory for dev-mode settings backed by an in-memory database.

    Dev auth is on, with a test-only JWT secret and dev API key; ``/docs`` stays off unless a
    test passes ``enable_docs=True``.
    """

    def _factory(**overrides: Any) -> EncryptedIRSettings:
        values: dict[str, Any] = {
            "environment": "dev",
            "database_url": "sqlite+pysqlite:///:memory:",
            "master_key": os.urandom(32),
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
def app(settings_factory: SettingsFactory) -> FastAPI:
    """Create a fresh app with reset process-global metrics and rate limits."""
    reset_metrics()
    set_rate_limiter(RateLimiter())
    return create_app(settings_factory())


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


@pytest.fixture()
def auth_headers(make_token: TokenFactory) -> dict[str, str]:
    """Headers for tenant ``test-tenant-001`` with admin, write and read roles."""
    return bearer(make_token("test-tenant-001", ["admin", "write", "read"]))


@pytest.fixture()
def read_only_headers(make_token: TokenFactory) -> dict[str, str]:
    """Headers for tenant ``test-tenant-001`` with the read role only."""
    return bearer(make_token("test-tenant-001", ["read"]))
