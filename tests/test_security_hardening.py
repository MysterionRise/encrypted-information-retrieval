"""Tests for CTO-impact security hardening paths."""

from __future__ import annotations

import os
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from sqlalchemy import select

from encrypted_ir.api.dependencies.auth import AuthConfig, OIDCVerifier, _extract_tenant_from_jwt
from encrypted_ir.api.main import create_app
from encrypted_ir.database import audit_log_table
from encrypted_ir.master_key import resolve_master_key
from encrypted_ir.settings import EncryptedIRSettings


class _FakeSigningKey:
    def __init__(self, key):
        self.key = key


class _FakeJWKSClient:
    def __init__(self, key):
        self._key = key

    def get_signing_key_from_jwt(self, token):
        return _FakeSigningKey(self._key)


class _FakeKMSProvider:
    def __init__(self, plaintext):
        self._plaintext = plaintext

    def generate_data_key(self, key_spec="AES_256"):
        return self._plaintext, b"encrypted"

    def encrypt(self, plaintext):
        return b"wrapped-" + plaintext

    def decrypt(self, ciphertext):
        return self._plaintext

    def get_key_id(self):
        return "alias/test"

    def key_exists(self):
        return True


def _rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def _oidc_token(
    private_key,
    issuer="https://issuer.example",
    audience="encrypted-ir",
    overrides=None,
    omit=None,
):
    now = int(time.time())
    payload = {
        "iss": issuer,
        "aud": audience,
        "sub": "user-1",
        "tenant_id": "tenant-oidc",
        "roles": ["read", "write"],
        "iat": now,
        "exp": now + 300,
    }
    payload.update(overrides or {})
    for key in omit or []:
        payload.pop(key, None)
    return jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )


def test_oidc_verifier_accepts_valid_token():
    private_key, public_key = _rsa_keys()
    config = AuthConfig(
        dev_auth_enabled=False,
        oidc_issuer="https://issuer.example",
        oidc_audience="encrypted-ir",
        oidc_jwks_url="https://issuer.example/.well-known/jwks.json",
    )
    verifier = OIDCVerifier(config, jwks_client=_FakeJWKSClient(public_key))

    payload = verifier.decode(_oidc_token(private_key))
    tenant = _extract_tenant_from_jwt(payload, config)

    assert tenant.tenant_id == "tenant-oidc"
    assert {role.value for role in tenant.roles} == {"read", "write"}


def test_oidc_verifier_rejects_bad_issuer():
    private_key, public_key = _rsa_keys()
    config = AuthConfig(
        dev_auth_enabled=False,
        oidc_issuer="https://issuer.example",
        oidc_audience="encrypted-ir",
        oidc_jwks_url="https://issuer.example/.well-known/jwks.json",
    )
    verifier = OIDCVerifier(config, jwks_client=_FakeJWKSClient(public_key))

    with pytest.raises(Exception):
        verifier.decode(_oidc_token(private_key, issuer="https://evil.example"))


def test_settings_prod_rejects_dev_auth_and_raw_master_key():
    settings = EncryptedIRSettings(
        environment="prod",
        master_key=os.urandom(32),
        raw_master_key_configured=True,
        dev_auth_enabled=True,
        auto_create_tables=False,
    )

    with pytest.raises(ValueError):
        settings.validate()


def test_settings_prod_requires_oidc_and_kms():
    settings = EncryptedIRSettings(
        environment="prod",
        master_key=None,
        dev_auth_enabled=False,
        auto_create_tables=False,
    )

    with pytest.raises(ValueError, match="OIDC"):
        settings.validate()


def test_kms_master_key_resolution_with_fake_provider():
    plaintext = os.urandom(32)
    settings = EncryptedIRSettings(
        environment="test",
        master_key=None,
        kms_provider="aws",
        aws_kms_key_id="alias/test",
        encrypted_master_key=b"encrypted",
    )

    resolved, source = resolve_master_key(settings, lambda _: _FakeKMSProvider(plaintext))

    assert resolved == plaintext
    assert source == "aws-kms"


def test_ready_endpoint_reports_ready_in_local_mode():
    app = create_app()
    client = TestClient(app, raise_server_exceptions=False)

    resp = client.get("/ready")

    assert resp.status_code == 200
    assert resp.json()["status"] == "ready"


def test_ready_endpoint_returns_503_when_not_ready():
    settings = EncryptedIRSettings(
        environment="test",
        master_key=os.urandom(32),
        auto_create_tables=False,
    )
    app = create_app(settings)
    client = TestClient(app, raise_server_exceptions=False)

    resp = client.get("/ready")

    assert resp.status_code == 503
    assert resp.json()["status"] == "not_ready"


@pytest.mark.parametrize(
    ("token_kwargs", "expected_status"),
    [
        ({"omit": ["tenant_id"]}, 401),
        ({"omit": ["roles"]}, 401),
        ({"overrides": {"roles": []}}, 401),
        ({"overrides": {"roles": ["owner"]}}, 403),
    ],
)
def test_oidc_document_flow_rejects_missing_or_unknown_claims(token_kwargs, expected_status):
    private_key, public_key = _rsa_keys()
    settings = EncryptedIRSettings(
        environment="test",
        master_key=os.urandom(32),
        dev_auth_enabled=False,
        auto_create_tables=True,
        oidc_issuer="https://issuer.example",
        oidc_audience="encrypted-ir",
        oidc_jwks_url="https://issuer.example/jwks",
    )
    app = create_app(settings)
    app.state.oidc_verifier = OIDCVerifier(
        app.state.auth_config,
        jwks_client=_FakeJWKSClient(public_key),
    )
    client = TestClient(app, raise_server_exceptions=False)
    token = _oidc_token(private_key, **token_kwargs)

    resp = client.post(
        "/v1/documents",
        json={"doc_id": "bad-claims-doc", "content": "OIDC regulated retrieval document"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert resp.status_code == expected_status


def test_document_operations_write_sanitized_audit_rows():
    app = create_app()
    client = TestClient(app, raise_server_exceptions=False)
    headers = {"X-API-Key": "local-demo-key"}

    client.post(
        "/v1/documents",
        json={"doc_id": "audit-doc", "content": "secret fraud risk content"},
        headers=headers,
    )
    client.post(
        "/v1/documents/search",
        json={"query": "fraud risk"},
        headers=headers,
    )
    client.get("/v1/documents/audit-doc", headers=headers)
    client.post(
        "/v1/rag/retrieve",
        json={"query": "fraud", "include_plaintext": True},
        headers=headers,
    )

    with app.state.database_engine.connect() as conn:
        rows = conn.execute(select(audit_log_table.c.entry_json)).all()

    endpoint_records = [row.entry_json for row in rows if "event_type" in row.entry_json]
    event_types = {record["event_type"] for record in endpoint_records}
    serialized = str(endpoint_records)
    assert {"document.encrypt", "document.search", "document.decrypt", "rag.retrieve"}.issubset(
        event_types
    )
    assert "secret fraud risk content" not in serialized


def test_document_operation_failures_write_sanitized_audit_rows():
    app = create_app()
    client = TestClient(app, raise_server_exceptions=False)
    headers = {"X-API-Key": "local-demo-key"}

    client.post(
        "/v1/documents",
        json={"doc_id": "failure-doc", "content": "sensitive failure audit content"},
        headers=headers,
    )
    duplicate = client.post(
        "/v1/documents",
        json={"doc_id": "failure-doc", "content": "sensitive failure audit content"},
        headers=headers,
    )
    missing = client.get("/v1/documents/missing-doc", headers=headers)

    def _raise_search(*args, **kwargs):
        raise RuntimeError("search query and tokens must not be logged")

    app.state.document_service.search_documents = _raise_search
    search = client.post(
        "/v1/documents/search",
        json={"query": "raw search query", "operator": "AND"},
        headers=headers,
    )

    def _raise_rag(*args, **kwargs):
        raise RuntimeError("raw query and plaintext must not be logged")

    app.state.document_service.retrieve_for_rag = _raise_rag
    rag = client.post(
        "/v1/rag/retrieve",
        json={"query": "raw query text", "include_plaintext": True},
        headers=headers,
    )

    assert duplicate.status_code == 400
    assert missing.status_code == 404
    assert search.status_code == 500
    assert rag.status_code == 500

    with app.state.database_engine.connect() as conn:
        rows = conn.execute(select(audit_log_table.c.entry_json)).all()

    failure_records = [row.entry_json for row in rows if row.entry_json.get("success") is False]
    event_types = {record["event_type"] for record in failure_records}
    serialized = str(failure_records)
    assert {"document.encrypt", "document.search", "document.decrypt", "rag.retrieve"}.issubset(
        event_types
    )
    assert "sensitive failure audit content" not in serialized
    assert "raw search query" not in serialized
    assert "raw query text" not in serialized
    assert "search query and tokens must not be logged" not in serialized
    assert "raw query and plaintext must not be logged" not in serialized


def test_dev_api_key_auth_is_rejected_when_dev_auth_disabled():
    settings = EncryptedIRSettings(
        environment="test",
        master_key=os.urandom(32),
        dev_auth_enabled=False,
        auto_create_tables=True,
        oidc_issuer="https://issuer.example",
        oidc_audience="encrypted-ir",
        oidc_jwks_url="https://issuer.example/jwks",
    )
    app = create_app(settings)
    client = TestClient(app, raise_server_exceptions=False)

    resp = client.post(
        "/v1/documents",
        json={"doc_id": "x", "content": "data"},
        headers={"X-API-Key": "local-demo-key"},
    )

    assert resp.status_code == 401


def test_oidc_authenticated_document_flow():
    private_key, public_key = _rsa_keys()
    settings = EncryptedIRSettings(
        environment="test",
        master_key=os.urandom(32),
        dev_auth_enabled=False,
        auto_create_tables=True,
        oidc_issuer="https://issuer.example",
        oidc_audience="encrypted-ir",
        oidc_jwks_url="https://issuer.example/jwks",
    )
    app = create_app(settings)
    app.state.oidc_verifier = OIDCVerifier(
        app.state.auth_config,
        jwks_client=_FakeJWKSClient(public_key),
    )
    client = TestClient(app, raise_server_exceptions=False)
    headers = {"Authorization": f"Bearer {_oidc_token(private_key)}"}

    ingest = client.post(
        "/v1/documents",
        json={"doc_id": "oidc-doc", "content": "OIDC regulated retrieval document"},
        headers=headers,
    )
    retrieve = client.post(
        "/v1/rag/retrieve",
        json={"query": "regulated retrieval", "include_plaintext": True},
        headers=headers,
    )

    assert ingest.status_code == 200
    assert retrieve.status_code == 200
    assert retrieve.json()["candidates"][0]["doc_id"] == "oidc-doc"
