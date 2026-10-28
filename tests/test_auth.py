"""Tests for auth and HTTP-surface hardening (issue #41).

Covers settings refusal at startup, dev and OIDC token validation, generic error bodies,
fail-closed configuration, request body limits, request IDs, CORS, readiness, rate-bounded
auditing of rejected requests, and that a slow JWKS fetch does not block the event loop.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import subprocess
import sys
import time
from types import SimpleNamespace
from typing import Any

import anyio
import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient
from sqlalchemy import select
from starlette.responses import JSONResponse

from encrypted_ir.api.dependencies.auth import (
    AuthConfig,
    AuthenticationError,
    OIDCVerifier,
)
from encrypted_ir.api.dependencies.rate_limiter import (
    RateLimitConfig,
    RateLimiter,
)
from encrypted_ir.api.main import create_app
from encrypted_ir.api.middleware import (
    BodySizeLimitMiddleware,
    RequestBodyTooLargeError,
    SecurityAuditLimiter,
    sanitize_request_id,
)
from encrypted_ir.api.routes import admin
from encrypted_ir.database import audit_log_table
from encrypted_ir.settings import EncryptedIRSettings
from tests.conftest import TEST_JWT_SECRET, bearer, metric

ISSUER = "https://issuer.example"
AUDIENCE = "encrypted-ir"
SEARCH = "/v1/documents/search"
SEARCH_BODY = {"query": "fraud"}
GENERIC_401 = {"detail": "Not authenticated"}


@pytest.fixture()
def anyio_backend() -> str:
    return "asyncio"


def _dev_token(payload: dict[str, Any], secret: str = TEST_JWT_SECRET, alg: str = "HS256") -> str:
    return jwt.encode(payload, secret, algorithm=alg)


def _claims(**overrides: Any) -> dict[str, Any]:
    now = int(time.time())
    claims: dict[str, Any] = {
        "sub": "user-1",
        "tenant_id": "tenant-a",
        "roles": ["read"],
        "iat": now,
        "exp": now + 300,
    }
    claims.update(overrides)
    return {key: value for key, value in claims.items() if value is not None}


def _audit_rows(app) -> list[tuple[str, dict[str, Any]]]:
    with app.state.database_engine.connect() as conn:
        rows = conn.execute(select(audit_log_table.c.tenant_id, audit_log_table.c.entry_json))
        return [(row.tenant_id, row.entry_json) for row in rows]


def _security_rows(app) -> list[tuple[str, dict[str, Any]]]:
    events = {"auth.failure", "authz.failure", "rate_limit.exceeded"}
    return [(tenant, entry) for tenant, entry in _audit_rows(app) if entry["event_type"] in events]


def _prod_settings(**overrides: Any) -> EncryptedIRSettings:
    values: dict[str, Any] = {
        "environment": "prod",
        "master_key": None,
        "generated_ephemeral_master_key": False,
        "auto_create_tables": False,
        "dev_auth_enabled": False,
        "oidc_issuer": ISSUER,
        "oidc_audience": AUDIENCE,
        "oidc_jwks_url": f"{ISSUER}/jwks",
        "kms_provider": "aws",
        "aws_kms_key_id": "alias/test",
        "encrypted_master_key": b"wrapped",
        "cors_origins": ["https://app.example"],
    }
    values.update(overrides)
    return EncryptedIRSettings(**values)


# =============================================================================
# Settings: refuse unsafe configurations at startup
# =============================================================================


class TestSettingsValidation:
    def test_dev_auth_is_off_by_default(self):
        assert EncryptedIRSettings().dev_auth_enabled is False

    @pytest.mark.parametrize("environment", ["test", "prod"])
    def test_dev_auth_requires_dev_environment(self, settings_factory, environment):
        with pytest.raises(ValueError, match="ENCRYPTED_IR_ENV=dev|must be"):
            settings_factory(environment=environment).validate()

    @pytest.mark.parametrize("secret", [None, "", "x" * 31])
    def test_dev_auth_requires_a_32_byte_secret(self, settings_factory, secret):
        with pytest.raises(ValueError, match="ENCRYPTED_IR_JWT_SECRET"):
            settings_factory(jwt_secret=secret).validate()

    def test_32_byte_secret_is_accepted(self, settings_factory):
        settings_factory(jwt_secret="x" * 32).validate()

    def test_create_app_refuses_dev_auth_without_secret(self):
        with pytest.raises(ValueError, match="ENCRYPTED_IR_JWT_SECRET"):
            create_app(EncryptedIRSettings(dev_auth_enabled=True))

    @pytest.mark.parametrize(
        "algorithms", [("HS256",), ("RS256", "HS256"), ("none",), ("RS384",), ()]
    )
    def test_oidc_algorithms_must_be_asymmetric_allowlist(self, algorithms):
        with pytest.raises(ValueError, match="ENCRYPTED_IR_OIDC_ALGORITHMS"):
            EncryptedIRSettings(oidc_algorithms=algorithms).validate()

    def test_allowed_oidc_algorithms(self):
        EncryptedIRSettings(oidc_algorithms=("RS256", "PS256", "ES256")).validate()

    @pytest.mark.parametrize("tenant", ["_system", "", "a" * 129, "has space"])
    def test_dev_tenant_id_must_be_valid(self, settings_factory, tenant):
        with pytest.raises(ValueError, match="ENCRYPTED_IR_DEV_TENANT_ID"):
            settings_factory(dev_tenant_id=tenant).validate()

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("jwt_leeway_seconds", -1),
            ("jwt_leeway_seconds", 301),
            ("jwks_timeout_seconds", 0),
            ("jwks_timeout_seconds", 61),
            ("max_body_bytes", 0),
        ],
    )
    def test_numeric_bounds(self, settings_factory, field, value):
        with pytest.raises(ValueError):
            settings_factory(**{field: value}).validate()

    def test_prod_rejects_wildcard_cors(self):
        _prod_settings().validate()
        with pytest.raises(ValueError, match="CORS"):
            _prod_settings(cors_origins=["*"]).validate()

    def test_prod_rejects_dev_auth(self):
        with pytest.raises(ValueError, match="ENCRYPTED_IR_DEV_AUTH_ENABLED"):
            _prod_settings(dev_auth_enabled=True, jwt_secret="x" * 32).validate()

    def test_secrets_are_not_in_repr(self, settings_factory):
        settings = settings_factory(dev_api_key="dev-api-key-value")
        text = repr(settings)

        assert TEST_JWT_SECRET not in text
        assert "dev-api-key-value" not in text
        assert repr(settings.master_key) not in text
        assert TEST_JWT_SECRET not in repr(AuthConfig.from_settings(settings))


@pytest.fixture()
def clean_env(monkeypatch):
    for name in list(os.environ):
        if name.startswith("ENCRYPTED_IR_") or name == "DATABASE_URL":
            monkeypatch.delenv(name)
    return monkeypatch


class TestSettingsFromEnv:
    def test_defaults(self, clean_env):
        settings = EncryptedIRSettings.from_env()

        assert settings.dev_auth_enabled is False
        assert settings.jwt_secret is None
        assert settings.dev_api_key is None
        assert settings.enable_docs is False
        assert settings.oidc_algorithms == ("RS256",)
        assert settings.max_body_bytes == 10 * 1024 * 1024

    def test_dev_auth_without_secret_fails(self, clean_env):
        clean_env.setenv("ENCRYPTED_IR_DEV_AUTH_ENABLED", "true")
        with pytest.raises(ValueError, match="ENCRYPTED_IR_JWT_SECRET"):
            EncryptedIRSettings.from_env()

    def test_parses_auth_and_http_settings(self, clean_env):
        for name, value in {
            "ENCRYPTED_IR_DEV_AUTH_ENABLED": "true",
            "ENCRYPTED_IR_JWT_SECRET": TEST_JWT_SECRET,
            "ENCRYPTED_IR_DEV_API_KEY": "env-dev-key",
            "ENCRYPTED_IR_DEV_TENANT_ID": "env-tenant",
            "ENCRYPTED_IR_JWT_LEEWAY_SECONDS": "10",
            "ENCRYPTED_IR_OIDC_ALGORITHMS": "RS256, ES256",
            "ENCRYPTED_IR_JWKS_TIMEOUT_SECONDS": "2.5",
            "ENCRYPTED_IR_ENABLE_DOCS": "true",
            "ENCRYPTED_IR_MAX_BODY_BYTES": "2048",
        }.items():
            clean_env.setenv(name, value)

        settings = EncryptedIRSettings.from_env()

        assert settings.dev_auth_enabled is True
        assert settings.jwt_secret == TEST_JWT_SECRET
        assert settings.dev_api_key == "env-dev-key"
        assert settings.dev_tenant_id == "env-tenant"
        assert settings.jwt_leeway_seconds == 10
        assert settings.oidc_algorithms == ("RS256", "ES256")
        assert settings.jwks_timeout_seconds == 2.5
        assert settings.enable_docs is True
        assert settings.max_body_bytes == 2048

    @pytest.mark.parametrize(
        "name",
        [
            "ENCRYPTED_IR_JWT_LEEWAY_SECONDS",
            "ENCRYPTED_IR_JWKS_TIMEOUT_SECONDS",
            "ENCRYPTED_IR_MAX_BODY_BYTES",
        ],
    )
    def test_bad_numbers_name_the_variable(self, clean_env, name):
        clean_env.setenv(name, "lots")
        with pytest.raises(ValueError, match=name):
            EncryptedIRSettings.from_env()


def test_importing_the_api_reads_no_environment():
    """The old module raised at import when dev auth was off and no secret was set."""
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("ENCRYPTED_IR_") and key != "DATABASE_URL"
    }
    env["ENCRYPTED_IR_DEV_AUTH_ENABLED"] = "false"
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-W", "error::RuntimeWarning", "-c", "import encrypted_ir.api.main"],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr


# =============================================================================
# Dev tokens and the dev API key
# =============================================================================


class TestDevTokens:
    def _search(self, client, token):
        return client.post(SEARCH, json=SEARCH_BODY, headers=bearer(token))

    def test_valid_token(self, client):
        assert self._search(client, _dev_token(_claims())).status_code == 200

    @pytest.mark.parametrize(
        "overrides",
        [
            {"exp": int(time.time()) - 120},
            {"exp": None},
            {"iat": None},
            {"iat": int(time.time()) + 3600},
            {"tenant_id": None},
            {"tenant_id": "_system"},
            {"tenant_id": "_anything"},
            {"tenant_id": "a" * 129},
            {"tenant_id": "a" * 256},
            {"tenant_id": 123},
            {"tenant_id": ["tenant-a"]},
            {"tenant_id": ""},
            {"tenant_id": "tenant/a"},
            {"tenant_id": "tenant-a\n"},
            {"roles": None},
            {"roles": []},
            {"roles": ""},
            {"roles": [1]},
            {"roles": {"read": True}},
        ],
    )
    def test_rejected_claims_return_generic_401(self, client, overrides):
        resp = self._search(client, _dev_token(_claims(**overrides)))

        assert resp.status_code == 401
        assert resp.json() == GENERIC_401
        assert resp.headers["www-authenticate"] == "Bearer"

    @pytest.mark.parametrize("roles", [["owner"], ["read", "owner"]])
    def test_unknown_roles_return_403(self, client, roles):
        resp = self._search(client, _dev_token(_claims(roles=roles)))

        assert resp.status_code == 403
        assert resp.json() == {"detail": "Insufficient permissions"}

    def test_space_separated_roles_and_longest_tenant_are_accepted(self, client):
        token = _dev_token(_claims(tenant_id="a" * 128, roles="read write"))
        assert self._search(client, token).status_code == 200

    def test_expiry_within_leeway_is_accepted(self, client):
        token = _dev_token(_claims(exp=int(time.time()) - 10))
        assert self._search(client, token).status_code == 200

    def test_expiry_outside_zero_leeway_is_rejected(self, settings_factory):
        client = TestClient(create_app(settings_factory(jwt_leeway_seconds=0)))
        token = _dev_token(_claims(exp=int(time.time()) - 10))
        assert self._search(client, token).status_code == 401

    @pytest.mark.filterwarnings("ignore::jwt.warnings.InsecureKeyLengthWarning")
    @pytest.mark.parametrize("alg", ["HS384", "HS512"])
    def test_only_hs256_is_accepted_for_dev_tokens(self, client, alg):
        assert self._search(client, _dev_token(_claims(), alg=alg)).status_code == 401

    def test_wrong_secret(self, client):
        token = _dev_token(_claims(), secret="another-secret-that-is-32-bytes-long")
        assert self._search(client, token).status_code == 401

    def test_dev_api_key_is_off_unless_configured(self, settings_factory):
        client = TestClient(create_app(settings_factory(dev_api_key=None)))
        for key in ["", "local-demo-key", "None"]:
            resp = client.post(SEARCH, json=SEARCH_BODY, headers={"X-API-Key": key})
            assert resp.status_code == 401

    def test_bearer_without_any_bearer_auth_configured(self, settings_factory):
        settings = settings_factory(environment="test", dev_auth_enabled=False)
        client = TestClient(create_app(settings))

        assert self._search(client, _dev_token(_claims())).status_code == 401


class TestFailClosed:
    def test_missing_auth_config_rejects_everything(self, app, client):
        del app.state.auth_config

        resp = client.post(SEARCH, json=SEARCH_BODY, headers={"X-API-Key": "test-only-dev-api-key"})

        assert resp.status_code == 401

    def test_missing_oidc_verifier_rejects_bearer_tokens(self, oidc):
        del oidc.app.state.oidc_verifier

        assert oidc.search(oidc.token()).status_code == 401

    def test_verifier_without_jwks_url(self):
        verifier = OIDCVerifier(AuthConfig())
        with pytest.raises(AuthenticationError) as exc_info:
            verifier.decode("a.b.c")
        assert exc_info.value.reason == "oidc_not_configured"

    def test_jwks_client_uses_the_configured_timeout(self):
        verifier = OIDCVerifier(
            AuthConfig(oidc_jwks_url=f"{ISSUER}/jwks", jwks_timeout_seconds=2.5)
        )
        client = verifier._client()

        assert isinstance(client, jwt.PyJWKClient)
        assert client.timeout == 2.5
        assert verifier._client() is client


# =============================================================================
# OIDC tokens
# =============================================================================


class _FakeJWKS:
    def __init__(self, keys: dict[str, Any]):
        self._keys = keys

    def get_signing_key_from_jwt(self, token: str) -> Any:
        kid = jwt.get_unverified_header(token).get("kid")
        if kid not in self._keys:
            raise jwt.PyJWKClientError(f"Unable to find a signing key that matches: {kid}")
        return SimpleNamespace(key=self._keys[kid])


class _UnreachableJWKS:
    def get_signing_key_from_jwt(self, token: str) -> Any:
        raise jwt.PyJWKClientConnectionError("Fail to fetch data from the url, err: timed out")


class _OIDCHarness:
    def __init__(self, settings: EncryptedIRSettings):
        self.rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.ec_key = ec.generate_private_key(ec.SECP256R1())
        self.app = create_app(settings)
        self.app.state.oidc_verifier = OIDCVerifier(
            self.app.state.auth_config,
            jwks_client=_FakeJWKS(
                {"rsa": self.rsa_key.public_key(), "ec": self.ec_key.public_key()}
            ),
        )
        self.client = TestClient(self.app, raise_server_exceptions=False)

    def claims(self, **overrides: Any) -> dict[str, Any]:
        return _claims(**{"iss": ISSUER, "aud": AUDIENCE, **overrides})

    def token(self, alg: str = "RS256", kid: str = "rsa", key: Any = None, **overrides) -> str:
        claims = self.claims(**overrides)
        signing_key = key or (self.ec_key if kid == "ec" else self.rsa_key)
        return jwt.encode(claims, signing_key, algorithm=alg, headers={"kid": kid})

    def search(self, token: str) -> httpx.Response:
        return self.client.post(SEARCH, json=SEARCH_BODY, headers=bearer(token))


def _oidc_settings(**overrides: Any) -> EncryptedIRSettings:
    values: dict[str, Any] = {
        "environment": "test",
        "master_key": os.urandom(32),
        "auto_create_tables": True,
        "oidc_issuer": ISSUER,
        "oidc_audience": AUDIENCE,
        "oidc_jwks_url": f"{ISSUER}/jwks",
    }
    values.update(overrides)
    return EncryptedIRSettings(**values)


@pytest.fixture()
def oidc() -> _OIDCHarness:
    return _OIDCHarness(_oidc_settings())


class TestOIDCTokens:
    def test_valid_token(self, oidc):
        assert oidc.search(oidc.token()).status_code == 200

    @pytest.mark.parametrize(
        "overrides",
        [
            {"exp": int(time.time()) - 120},
            {"exp": None},
            {"iat": None},
            {"aud": None},
            {"iss": None},
            {"aud": "another-service"},
            {"iss": "https://evil.example"},
            {"tenant_id": "_system"},
            {"roles": None},
        ],
    )
    def test_rejected_claims(self, oidc, overrides):
        resp = oidc.search(oidc.token(**overrides))

        assert resp.status_code == 401
        assert resp.json() == GENERIC_401

    def test_unknown_kid(self, oidc):
        assert oidc.search(oidc.token(kid="rotated-away", key=oidc.rsa_key)).status_code == 401

    def test_unreachable_jwks_is_401_not_500(self, oidc):
        oidc.app.state.oidc_verifier = OIDCVerifier(
            oidc.app.state.auth_config, jwks_client=_UnreachableJWKS()
        )
        assert oidc.search(oidc.token()).status_code == 401

    def test_dev_hs256_token_is_rejected(self, oidc):
        token = jwt.encode(oidc.claims(), TEST_JWT_SECRET, headers={"kid": "rsa"})
        assert oidc.search(token).status_code == 401

    def test_hmac_keyed_with_the_public_key_is_rejected(self, oidc):
        """The classic algorithm confusion: HS256 using the RSA public key PEM as the secret."""
        pem = oidc.rsa_key.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        )

        def b64(data: bytes) -> bytes:
            return base64.urlsafe_b64encode(data).rstrip(b"=")

        signing_input = (
            b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "rsa"}).encode())
            + b"."
            + b64(json.dumps(oidc.claims()).encode())
        )
        signature = b64(hmac.new(pem, signing_input, hashlib.sha256).digest())
        token = (signing_input + b"." + signature).decode()

        assert oidc.search(token).status_code == 401

    def test_alg_none_is_rejected(self, oidc):
        unsigned = jwt.encode(oidc.claims(), None, algorithm="none", headers={"kid": "rsa"})
        assert oidc.search(unsigned).status_code == 401

    def test_only_configured_algorithms_are_accepted(self):
        harness = _OIDCHarness(_oidc_settings(oidc_algorithms=("ES256",)))

        assert harness.search(harness.token(alg="ES256", kid="ec")).status_code == 200
        assert harness.search(harness.token(alg="RS256", kid="rsa")).status_code == 401

    def test_dev_api_key_is_ignored_without_dev_auth(self, oidc):
        resp = oidc.client.post(
            SEARCH, json=SEARCH_BODY, headers={"X-API-Key": "test-only-dev-api-key"}
        )
        assert resp.status_code == 401


# =============================================================================
# Error bodies never carry exception text
# =============================================================================


class TestGenericErrors:
    SECRET_TEXT = "tenant-b key_7f3a password=hunter2"

    @pytest.mark.parametrize(
        ("exc", "status_code", "error"),
        [
            (ValueError, 400, "bad_request"),
            (KeyError, 404, "not_found"),
            (RuntimeError, 500, "internal_error"),
        ],
    )
    def test_exception_text_is_not_returned(
        self, app, client, auth_headers, exc, status_code, error
    ):
        def _raise(*args, **kwargs):
            raise exc(self.SECRET_TEXT)

        app.state.document_service.search_documents = _raise
        resp = client.post(SEARCH, json=SEARCH_BODY, headers=auth_headers)

        assert resp.status_code == status_code
        assert resp.json()["error"] == error
        assert "hunter2" not in resp.text
        assert "tenant-b" not in resp.text


# =============================================================================
# Request IDs
# =============================================================================


class TestRequestId:
    @pytest.mark.parametrize("value", ["a" * 64, "trace-1.2_3"])
    def test_safe_ids_are_kept(self, client, value):
        assert (
            client.get("/health", headers={"X-Request-ID": value}).headers["x-request-id"] == value
        )

    @pytest.mark.parametrize("value", ["a" * 65, "has space", "semi;colon", "<script>", ""])
    def test_unsafe_ids_are_replaced(self, client, value):
        returned = client.get("/health", headers={"X-Request-ID": value}).headers["x-request-id"]

        assert returned != value
        assert sanitize_request_id(returned) == returned

    def test_sanitize_none(self):
        assert len(sanitize_request_id(None)) == 36


# =============================================================================
# Request body limit
# =============================================================================


class TestBodyLimit:
    @pytest.fixture()
    def small_client(self, settings_factory):
        return TestClient(
            create_app(settings_factory(max_body_bytes=1024)), raise_server_exceptions=False
        )

    def _doc(self, size: int) -> dict[str, str]:
        return {"doc_id": "big", "content": "x" * size}

    def test_body_under_limit(self, small_client, auth_headers):
        resp = small_client.post("/v1/documents", json=self._doc(100), headers=auth_headers)
        assert resp.status_code == 200

    def test_declared_length_over_limit(self, small_client, auth_headers):
        resp = small_client.post("/v1/documents", json=self._doc(2000), headers=auth_headers)

        assert resp.status_code == 413
        assert resp.json()["error"] == "request_too_large"
        assert resp.json()["request_id"] == resp.headers["x-request-id"]

    def test_chunked_body_over_limit(self, small_client, auth_headers):
        def chunks():
            yield b'{"doc_id": "big", "content": "'
            yield b"x" * 2000
            yield b'"}'

        resp = small_client.post(
            "/v1/documents",
            content=chunks(),
            headers={**auth_headers, "Content-Type": "application/json"},
        )

        assert "content-length" not in {k.lower() for k in resp.request.headers}
        assert resp.status_code == 413
        assert resp.json()["error"] == "request_too_large"


async def _echo_app(scope, receive, send) -> None:
    body = b""
    while True:
        message = await receive()
        body += message.get("body", b"")
        if not message.get("more_body"):
            break
    await JSONResponse({"received": len(body)})(scope, receive, send)


async def _call_limited(headers: list[tuple[bytes, bytes]], chunks: list[bytes]) -> list[dict]:
    middleware = BodySizeLimitMiddleware(_echo_app, max_body_bytes=10)
    messages = [
        {"type": "http.request", "body": chunk, "more_body": i < len(chunks) - 1}
        for i, chunk in enumerate(chunks)
    ]
    sent: list[dict] = []

    async def receive():
        return messages.pop(0)

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/",
        "headers": headers,
        "query_string": b"",
        "state": {"request_id": "rid-1"},
    }
    await middleware(scope, receive, send)
    return sent


class TestBodyLimitMiddleware:
    @pytest.mark.anyio
    @pytest.mark.parametrize(
        "headers",
        [
            [(b"content-length", b"abc")],
            [(b"content-length", b"-1")],
            [(b"content-length", b"1, 1")],
            [(b"content-length", b"\xb2")],
            [(b"content-length", b"5"), (b"content-length", b"6")],
        ],
    )
    async def test_invalid_content_length_is_400(self, headers):
        sent = await _call_limited(headers, [b"hello"])

        assert sent[0]["status"] == 400
        assert b"Invalid Content-Length" in sent[1]["body"]
        assert b"rid-1" in sent[1]["body"]

    @pytest.mark.anyio
    async def test_repeated_equal_content_length_is_allowed(self):
        sent = await _call_limited([(b"content-length", b"5")] * 2, [b"hello"])
        assert sent[0]["status"] == 200

    @pytest.mark.anyio
    async def test_multi_chunk_stream_is_counted(self):
        assert (await _call_limited([], [b"12345", b"12345"]))[0]["status"] == 200
        with pytest.raises(RequestBodyTooLargeError):
            await _call_limited([], [b"12345", b"12345", b"1"])

    @pytest.mark.anyio
    async def test_non_http_scopes_pass_through(self):
        seen = []

        async def app(scope, receive, send):
            seen.append(scope["type"])

        await BodySizeLimitMiddleware(app, max_body_bytes=1)({"type": "lifespan"}, None, None)
        assert seen == ["lifespan"]


# =============================================================================
# CORS and docs
# =============================================================================


class TestCORS:
    ORIGIN = "http://localhost:3000"

    def _preflight(self, client, method="POST", headers="authorization,content-type", origin=None):
        return client.options(
            SEARCH,
            headers={
                "Origin": origin or self.ORIGIN,
                "Access-Control-Request-Method": method,
                "Access-Control-Request-Headers": headers,
            },
        )

    def test_explicit_origin_allows_credentials_and_listed_methods(self, client):
        resp = self._preflight(client, method="DELETE")

        assert resp.status_code == 200
        assert resp.headers["access-control-allow-origin"] == self.ORIGIN
        assert resp.headers["access-control-allow-credentials"] == "true"
        assert set(resp.headers["access-control-allow-methods"].split(", ")) == {
            "GET",
            "POST",
            "DELETE",
        }

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"method": "PUT"},
            {"headers": "x-evil"},
            {"origin": "https://evil.example"},
        ],
    )
    def test_disallowed_preflights(self, client, kwargs):
        assert self._preflight(client, **kwargs).status_code == 400

    def test_wildcard_origin_never_allows_credentials(self, settings_factory):
        client = TestClient(create_app(settings_factory(cors_origins=["*"])))
        resp = self._preflight(client, origin="https://anywhere.example")

        assert resp.headers["access-control-allow-origin"] == "*"
        assert "access-control-allow-credentials" not in resp.headers

    def test_request_id_is_exposed(self, client):
        resp = client.get("/health", headers={"Origin": self.ORIGIN})
        assert "X-Request-ID" in resp.headers["access-control-expose-headers"]


# =============================================================================
# Readiness reports booleans only
# =============================================================================


class TestReadiness:
    SECRET_TEXT = "postgresql://admin:hunter2@db.internal:5432"

    @pytest.fixture(autouse=True)
    def _capture_admin_warnings(self, caplog):
        caplog.set_level(logging.WARNING, logger="encrypted_ir.api.routes.admin")

    def test_database_failure_is_logged_not_returned(self, client, monkeypatch, caplog):
        def _fail(engine):
            raise RuntimeError(self.SECRET_TEXT)

        monkeypatch.setattr(admin, "database_connects", _fail)
        resp = client.get("/ready")

        assert resp.status_code == 503
        assert resp.json()["checks"]["database"] is False
        assert "hunter2" not in resp.text
        assert self.SECRET_TEXT in caplog.text

    def test_migration_failure_is_logged_not_returned(self, settings_factory, monkeypatch, caplog):
        client = TestClient(create_app(settings_factory(auto_create_tables=False)))

        def _fail(engine, url):
            raise RuntimeError(self.SECRET_TEXT)

        monkeypatch.setattr(admin, "migration_status", _fail)
        resp = client.get("/ready")

        assert resp.json()["checks"]["migrations"] is False
        assert "hunter2" not in resp.text
        assert self.SECRET_TEXT in caplog.text

    def test_revisions_are_not_returned(self, settings_factory, caplog):
        client = TestClient(create_app(settings_factory(auto_create_tables=False)))
        resp = client.get("/ready")

        assert resp.json()["checks"]["migrations"] is False
        assert "head" not in resp.text
        assert "not at head" in caplog.text

    def test_unknown_key_source(self, app, client):
        app.state.master_key_source = "unknown"
        assert client.get("/ready").json()["checks"]["key_provider"] is False


# =============================================================================
# Rejected requests: counters and rate-bounded audit rows
# =============================================================================


class TestSecurityEvents:
    def test_401_is_audited_under_system_tenant(self, app, client):
        token = _dev_token(_claims(exp=int(time.time()) - 120))
        client.post(SEARCH, json=SEARCH_BODY, headers={**bearer(token), "X-Request-ID": "r-401"})

        [(tenant, entry)] = _security_rows(app)
        assert tenant == "_system"
        assert entry["event_type"] == "auth.failure"
        assert entry["actor"] == "anonymous"
        assert entry["success"] is False
        assert entry["resource"] == SEARCH
        assert entry["request_id"] == "r-401"
        assert entry["details"] == {"status": 401, "method": "POST", "reason": "token_expired"}

    def test_403_is_audited_under_the_caller_tenant(self, app, client, read_only_headers):
        client.delete("/v1/documents/doc-1", headers=read_only_headers)

        [(tenant, entry)] = _security_rows(app)
        assert tenant == "test-tenant-001"
        assert entry["event_type"] == "authz.failure"
        assert entry["actor"] == "test-tenant-001-user"
        assert entry["resource"] == "/v1/documents/{doc_id}"
        assert entry["details"]["reason"] == "insufficient_role"

    @pytest.fixture()
    def one_search_per_minute(self, app):
        app.state.rate_limiter = RateLimiter({"document_search": RateLimitConfig(max_requests=1)})

    def test_429_is_audited_and_counted(self, app, client, auth_headers, one_search_per_minute):
        client.post(SEARCH, json=SEARCH_BODY, headers=auth_headers)
        resp = client.post(SEARCH, json=SEARCH_BODY, headers=auth_headers)

        assert resp.status_code == 429
        [(tenant, entry)] = _security_rows(app)
        assert tenant == "test-tenant-001"
        assert entry["event_type"] == "rate_limit.exceeded"
        assert entry["details"]["reason"] == "rate_limited"
        assert (
            metric(
                app,
                "encrypted_ir_auth_rejections_total",
                status="429",
                reason="rate_limited",
            )
            == 1
        )

    def test_audit_rows_are_rate_bounded_but_all_rejections_are_counted(self, app, client):
        app.state.security_audit_limiter = SecurityAuditLimiter(per_source=(3, 60))
        for _ in range(10):
            client.post(SEARCH, json=SEARCH_BODY)

        assert len(_security_rows(app)) == 3
        assert (
            metric(
                app,
                "encrypted_ir_auth_rejections_total",
                status="401",
                reason="missing_credentials",
            )
            == 10
        )
        assert metric(app, "encrypted_ir_security_audit_dropped_total", limit="per_source") == 7

    def test_audit_bound_is_per_source(self, app, settings_factory):
        app.state.security_audit_limiter = SecurityAuditLimiter(per_source=(2, 60))
        first = TestClient(app, client=("198.51.100.1", 1))
        second = TestClient(app, client=("198.51.100.2", 1))
        for _ in range(5):
            first.post(SEARCH, json=SEARCH_BODY)
        second.post(SEARCH, json=SEARCH_BODY)

        # The first client's flood did not use up the second client's audit allowance.
        assert len(_security_rows(app)) == 3

    def test_audit_bound_has_a_global_cap(self, app):
        app.state.security_audit_limiter = SecurityAuditLimiter(per_source=(5, 60), total=(4, 60))
        for i in range(6):
            TestClient(app, client=(f"198.51.100.{i}", 1)).post(SEARCH, json=SEARCH_BODY)

        assert len(_security_rows(app)) == 4
        assert metric(app, "encrypted_ir_security_audit_dropped_total", limit="total") == 2

    def test_forbidden_counter(self, app, client, read_only_headers):
        client.delete("/v1/documents/doc-1", headers=read_only_headers)
        assert (
            metric(
                app,
                "encrypted_ir_auth_rejections_total",
                status="403",
                reason="insufficient_role",
            )
            == 1
        )

    def test_audit_failure_does_not_change_the_response(self, app, client):
        def _broken(**kwargs):
            raise RuntimeError("audit store down")

        app.state.document_service.record_audit_event = _broken
        resp = client.post(SEARCH, json=SEARCH_BODY)

        assert resp.status_code == 401
        assert resp.json() == GENERIC_401

    def test_limiter_window_slides(self):
        now = [1000.0]
        limiter = SecurityAuditLimiter(per_source=(2, 60), clock=lambda: now[0])

        assert [limiter.allow("t") for _ in range(3)] == [None, None, "per_source"]
        now[0] += 61
        assert limiter.allow("t") is None


# =============================================================================
# A slow JWKS fetch must not block the event loop
# =============================================================================


class _SlowJWKS:
    def get_signing_key_from_jwt(self, token: str) -> Any:
        time.sleep(1.5)
        raise jwt.PyJWKClientConnectionError("timed out")


@pytest.mark.anyio
async def test_slow_jwks_does_not_block_health(oidc):
    """/health answers while a token verification is stuck on the JWKS endpoint.

    If token verification ran on the event loop, the loop would be blocked for the whole
    1.5 s fetch and /health could not complete until it ended.
    """
    oidc.app.state.oidc_verifier = OIDCVerifier(oidc.app.state.auth_config, jwks_client=_SlowJWKS())
    transport = httpx.ASGITransport(app=oidc.app)
    statuses: dict[str, int] = {}

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:

        async def slow_request() -> None:
            resp = await client.post(SEARCH, json=SEARCH_BODY, headers=bearer(oidc.token()))
            statuses["search"] = resp.status_code

        start = time.monotonic()
        async with anyio.create_task_group() as tg:
            tg.start_soon(slow_request)
            await anyio.sleep(0.2)
            health = await client.get("/health")
            health_done = time.monotonic() - start

    assert health.status_code == 200
    assert health_done < 0.8
    assert statuses["search"] == 401
