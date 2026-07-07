"""Comprehensive API tests for the encrypted IR REST API.

Tests cover:
- Health check and metrics endpoints
- Encryption/decryption endpoints
- Equality, range, and keyword search endpoints
- Authentication (JWT, API key, missing auth)
- Authorization (RBAC role enforcement)
- Rate limiting
- Error handling (validation, not found, server errors)
- Request ID tracing
- Request size limits
"""

from __future__ import annotations

import base64
import json

import pytest
from fastapi.testclient import TestClient

from encrypted_ir.api.dependencies.auth import (
    Role,
    TenantInfo,
    clear_api_keys,
    register_api_key,
)
from encrypted_ir.api.dependencies.rate_limiter import (
    RateLimitConfig,
    RateLimiter,
    set_rate_limiter,
)
from encrypted_ir.api.main import create_app
from encrypted_ir.api.routes.admin import reset_metrics
from encrypted_ir.api.routes.data import reset_ciphers
from encrypted_ir.api.routes.keys import reset_key_managers
from encrypted_ir.api.routes.search import reset_search_state
from encrypted_ir.blind_index import BlindIndexConfig

# --- Fixtures ---


@pytest.fixture()
def app():
    """Create a fresh app instance for each test."""
    reset_ciphers()
    reset_search_state()
    reset_key_managers()
    reset_metrics()
    clear_api_keys()
    set_rate_limiter(RateLimiter())
    return create_app()


@pytest.fixture()
def client(app):
    """Create test client."""
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture()
def auth_headers():
    """Register an API key and return auth headers for a write tenant."""
    tenant = TenantInfo(
        tenant_id="test-tenant-001",
        roles=[Role.ADMIN, Role.WRITE, Role.READ],
        subject="test-user",
    )
    register_api_key("test-api-key-write", tenant)
    return {"X-API-Key": "test-api-key-write"}


@pytest.fixture()
def read_only_headers():
    """Register a read-only API key."""
    tenant = TenantInfo(
        tenant_id="test-tenant-read",
        roles=[Role.READ],
        subject="read-user",
    )
    register_api_key("test-api-key-read", tenant)
    return {"X-API-Key": "test-api-key-read"}


@pytest.fixture()
def admin_headers():
    """Register an admin-only API key."""
    tenant = TenantInfo(
        tenant_id="test-tenant-admin",
        roles=[Role.ADMIN],
        subject="admin-user",
    )
    register_api_key("test-api-key-admin", tenant)
    return {"X-API-Key": "test-api-key-admin"}


def _make_jwt(payload: dict) -> str:
    """Create a simple unsigned JWT for testing (base64-encoded payload)."""
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(
        b"="
    )
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=")
    sig = base64.urlsafe_b64encode(b"test-sig").rstrip(b"=")
    return f"{header.decode()}.{body.decode()}.{sig.decode()}"


# =============================================================================
# Health & Metrics (no auth required)
# =============================================================================


class TestHealthCheck:
    def test_health_returns_200(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["version"] == "1.0.0"
        assert data["uptime_seconds"] >= 0

    def test_health_response_has_request_id(self, client):
        resp = client.get("/health")
        assert "x-request-id" in resp.headers

    def test_health_custom_request_id(self, client):
        resp = client.get("/health", headers={"X-Request-ID": "custom-id-123"})
        assert resp.headers["x-request-id"] == "custom-id-123"


class TestMetrics:
    def test_metrics_returns_200(self, client):
        resp = client.get("/metrics")
        assert resp.status_code == 200
        data = resp.json()
        assert "request_count" in data
        assert "error_count" in data
        assert "active_tenants" in data

    def test_metrics_counts_requests(self, client):
        client.get("/health")
        client.get("/health")
        resp = client.get("/metrics")
        data = resp.json()
        # At least the 2 health + 1 metrics request
        assert data["request_count"] >= 2


# =============================================================================
# Authentication
# =============================================================================


class TestAuth:
    def test_missing_auth_returns_401(self, client):
        resp = client.post("/v1/encrypt", json={"plaintext": "hello"})
        assert resp.status_code == 401

    def test_invalid_api_key_returns_401(self, client):
        resp = client.post(
            "/v1/encrypt",
            json={"plaintext": "hello"},
            headers={"X-API-Key": "bad-key"},
        )
        assert resp.status_code == 401

    def test_valid_api_key_succeeds(self, client, auth_headers):
        resp = client.post(
            "/v1/encrypt",
            json={"plaintext": "hello"},
            headers=auth_headers,
        )
        assert resp.status_code == 200

    def test_jwt_auth_succeeds(self, client):
        token = _make_jwt({"tenant_id": "jwt-tenant", "roles": ["write"], "sub": "user1"})
        resp = client.post(
            "/v1/encrypt",
            json={"plaintext": "hello"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200

    def test_jwt_missing_tenant_id_returns_401(self, client):
        token = _make_jwt({"sub": "user1", "roles": ["write"]})
        resp = client.post(
            "/v1/encrypt",
            json={"plaintext": "hello"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401

    def test_malformed_jwt_returns_401(self, client):
        resp = client.post(
            "/v1/encrypt",
            json={"plaintext": "hello"},
            headers={"Authorization": "Bearer not.a.valid.jwt"},
        )
        assert resp.status_code == 401


# =============================================================================
# Authorization (RBAC)
# =============================================================================


class TestAuthorization:
    def test_read_only_cannot_encrypt(self, client, read_only_headers):
        resp = client.post(
            "/v1/encrypt",
            json={"plaintext": "hello"},
            headers=read_only_headers,
        )
        assert resp.status_code == 403

    def test_read_only_can_search(self, client, read_only_headers):
        resp = client.post(
            "/v1/search/equality",
            json={
                "value": "test",
                "field_name": "email",
                "index_map": {},
            },
            headers=read_only_headers,
        )
        assert resp.status_code == 200

    def test_non_admin_cannot_rotate_key(self, client, read_only_headers):
        resp = client.post(
            "/v1/keys/rotate",
            json={"key_id": "some-key"},
            headers=read_only_headers,
        )
        assert resp.status_code == 403

    def test_admin_can_rotate_key(self, client, admin_headers):
        # First create a key by listing (which initializes the key manager)
        # We need to create a key first
        from encrypted_ir.api.routes.keys import _get_key_manager

        km = _get_key_manager("test-tenant-admin")
        key_id = km.create_key("deterministic")

        resp = client.post(
            "/v1/keys/rotate",
            json={"key_id": key_id},
            headers=admin_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["old_key_id"] == key_id
        assert data["new_key_id"] != key_id


# =============================================================================
# Encryption / Decryption
# =============================================================================


class TestEncryptDecrypt:
    def test_encrypt_aes_siv(self, client, auth_headers):
        resp = client.post(
            "/v1/encrypt",
            json={"plaintext": "sensitive data", "algorithm": "aes-siv"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["algorithm"] == "aes-siv"
        assert len(data["ciphertext"]) > 0
        assert "request_id" in data

    def test_encrypt_aes_gcm(self, client, auth_headers):
        resp = client.post(
            "/v1/encrypt",
            json={"plaintext": "sensitive data", "algorithm": "aes-gcm"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["algorithm"] == "aes-gcm"

    def test_encrypt_default_algorithm(self, client, auth_headers):
        resp = client.post(
            "/v1/encrypt",
            json={"plaintext": "hello"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["algorithm"] == "aes-siv"

    def test_encrypt_invalid_algorithm(self, client, auth_headers):
        resp = client.post(
            "/v1/encrypt",
            json={"plaintext": "hello", "algorithm": "rot13"},
            headers=auth_headers,
        )
        assert resp.status_code == 422

    def test_decrypt_aes_siv_roundtrip(self, client, auth_headers):
        # Encrypt
        enc_resp = client.post(
            "/v1/encrypt",
            json={"plaintext": "roundtrip test", "algorithm": "aes-siv"},
            headers=auth_headers,
        )
        assert enc_resp.status_code == 200
        ciphertext = enc_resp.json()["ciphertext"]

        # Decrypt
        dec_resp = client.post(
            "/v1/decrypt",
            json={"ciphertext": ciphertext, "algorithm": "aes-siv"},
            headers=auth_headers,
        )
        assert dec_resp.status_code == 200
        assert dec_resp.json()["plaintext"] == "roundtrip test"

    def test_decrypt_aes_gcm_roundtrip(self, client, auth_headers):
        enc_resp = client.post(
            "/v1/encrypt",
            json={"plaintext": "gcm roundtrip", "algorithm": "aes-gcm"},
            headers=auth_headers,
        )
        ciphertext = enc_resp.json()["ciphertext"]

        dec_resp = client.post(
            "/v1/decrypt",
            json={"ciphertext": ciphertext, "algorithm": "aes-gcm"},
            headers=auth_headers,
        )
        assert dec_resp.status_code == 200
        assert dec_resp.json()["plaintext"] == "gcm roundtrip"

    def test_encrypt_empty_plaintext_rejected(self, client, auth_headers):
        resp = client.post(
            "/v1/encrypt",
            json={"plaintext": ""},
            headers=auth_headers,
        )
        assert resp.status_code == 422

    def test_decrypt_invalid_ciphertext(self, client, auth_headers):
        resp = client.post(
            "/v1/decrypt",
            json={"ciphertext": base64.b64encode(b"not-valid").decode(), "algorithm": "aes-siv"},
            headers=auth_headers,
        )
        # Should get a 400 or 500 error from decryption failure
        assert resp.status_code in (400, 500)


# =============================================================================
# Equality Search
# =============================================================================


class TestEqualitySearch:
    def test_equality_search_match(self, client, auth_headers):
        # Build an index map using the same generator the API will use
        from encrypted_ir.api.routes.search import _get_blind_index

        generator = _get_blind_index("test-tenant-001")
        config = BlindIndexConfig(field_name="email", output_length=16, case_sensitive=False)
        idx = generator.create_index("alice@example.com", config)

        resp = client.post(
            "/v1/search/equality",
            json={
                "value": "alice@example.com",
                "field_name": "email",
                "index_map": {idx: "record-1"},
                "output_length": 16,
                "case_sensitive": False,
            },
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        assert data["matches"] == ["record-1"]

    def test_equality_search_no_match(self, client, auth_headers):
        resp = client.post(
            "/v1/search/equality",
            json={
                "value": "unknown@example.com",
                "field_name": "email",
                "index_map": {"fake-index": "record-1"},
            },
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["count"] == 0

    def test_equality_search_case_insensitive(self, client, auth_headers):
        from encrypted_ir.api.routes.search import _get_blind_index

        generator = _get_blind_index("test-tenant-001")
        config = BlindIndexConfig(field_name="email", output_length=16, case_sensitive=False)
        idx = generator.create_index("Alice@Example.COM", config)

        resp = client.post(
            "/v1/search/equality",
            json={
                "value": "alice@example.com",
                "field_name": "email",
                "index_map": {idx: "record-1"},
            },
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["count"] == 1


# =============================================================================
# Range Search
# =============================================================================


class TestRangeSearch:
    def test_range_search_finds_values_in_range(self, client, auth_headers):
        from encrypted_ir.api.routes.search import _get_ore

        ore = _get_ore("test-tenant-001")
        values = [100, 200, 300, 400, 500]
        encrypted = [base64.b64encode(ore.encrypt_int(v)).decode() for v in values]

        resp = client.post(
            "/v1/search/range",
            json={
                "encrypted_values": encrypted,
                "min_value": 200,
                "max_value": 400,
            },
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 3  # 200, 300, 400

    def test_range_search_no_min(self, client, auth_headers):
        from encrypted_ir.api.routes.search import _get_ore

        ore = _get_ore("test-tenant-001")
        encrypted = [base64.b64encode(ore.encrypt_int(v)).decode() for v in [10, 20, 30]]

        resp = client.post(
            "/v1/search/range",
            json={
                "encrypted_values": encrypted,
                "max_value": 20,
            },
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["count"] == 2  # 10, 20

    def test_range_search_no_max(self, client, auth_headers):
        from encrypted_ir.api.routes.search import _get_ore

        ore = _get_ore("test-tenant-001")
        encrypted = [base64.b64encode(ore.encrypt_int(v)).decode() for v in [10, 20, 30]]

        resp = client.post(
            "/v1/search/range",
            json={
                "encrypted_values": encrypted,
                "min_value": 20,
            },
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["count"] == 2  # 20, 30

    def test_range_search_empty_result(self, client, auth_headers):
        from encrypted_ir.api.routes.search import _get_ore

        ore = _get_ore("test-tenant-001")
        encrypted = [base64.b64encode(ore.encrypt_int(v)).decode() for v in [100, 200]]

        resp = client.post(
            "/v1/search/range",
            json={
                "encrypted_values": encrypted,
                "min_value": 500,
                "max_value": 600,
            },
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["count"] == 0


# =============================================================================
# Keyword Search
# =============================================================================


class TestKeywordSearch:
    def test_keyword_search_finds_matching_doc(self, client, auth_headers):
        from encrypted_ir.api.routes.search import _get_sse

        sse = _get_sse("test-tenant-001")
        _, tokens = sse.encrypt_document("quarterly fraud report analysis")
        token_list = list(tokens)

        resp = client.post(
            "/v1/search/keyword",
            json={
                "keyword": "fraud",
                "document_tokens": {"doc-1": token_list},
            },
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        assert data["matches"] == ["doc-1"]

    def test_keyword_search_no_match(self, client, auth_headers):
        resp = client.post(
            "/v1/search/keyword",
            json={
                "keyword": "nonexistent",
                "document_tokens": {"doc-1": ["token1", "token2"]},
            },
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["count"] == 0

    def test_keyword_search_multiple_docs(self, client, auth_headers):
        from encrypted_ir.api.routes.search import _get_sse

        sse = _get_sse("test-tenant-001")
        _, tokens1 = sse.encrypt_document("risk assessment quarterly report")
        _, tokens2 = sse.encrypt_document("annual compliance report")

        resp = client.post(
            "/v1/search/keyword",
            json={
                "keyword": "report",
                "document_tokens": {
                    "doc-1": list(tokens1),
                    "doc-2": list(tokens2),
                },
            },
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 2


# =============================================================================
# Durable Document Retrieval / RAG
# =============================================================================


class TestDurableDocuments:
    def test_document_ingest_search_and_get_roundtrip(self, client, auth_headers):
        ingest = client.post(
            "/v1/documents",
            json={
                "doc_id": "risk-report-1",
                "content": "Quarterly fraud risk report for regulated AI retrieval",
                "metadata": {"source": "portfolio-demo", "tier": "confidential"},
            },
            headers=auth_headers,
        )
        assert ingest.status_code == 200
        ingest_data = ingest.json()
        assert ingest_data["doc_id"] == "risk-report-1"
        assert ingest_data["algorithm"] == "aes-gcm"
        assert ingest_data["indexed_token_count"] > 0

        search = client.post(
            "/v1/documents/search",
            json={"query": "fraud risk", "operator": "AND", "limit": 5},
            headers=auth_headers,
        )
        assert search.status_code == 200
        search_data = search.json()
        assert search_data["count"] == 1
        assert search_data["matches"][0]["doc_id"] == "risk-report-1"
        assert search_data["matches"][0]["metadata"]["source"] == "portfolio-demo"

        get_resp = client.get("/v1/documents/risk-report-1", headers=auth_headers)
        assert get_resp.status_code == 200
        assert get_resp.json()["plaintext"] == (
            "Quarterly fraud risk report for regulated AI retrieval"
        )

    def test_rag_retrieve_can_include_plaintext(self, client, auth_headers):
        client.post(
            "/v1/documents",
            json={
                "doc_id": "aml-note-1",
                "content": "AML investigation notes mention suspicious transfer patterns",
                "metadata": {"case": "aml"},
            },
            headers=auth_headers,
        )

        resp = client.post(
            "/v1/rag/retrieve",
            json={"query": "suspicious transfer", "top_k": 3, "include_plaintext": True},
            headers=auth_headers,
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        assert data["candidates"][0]["doc_id"] == "aml-note-1"
        assert "suspicious transfer" in data["candidates"][0]["plaintext"]

    def test_duplicate_document_id_rejected(self, client, auth_headers):
        body = {"doc_id": "dup-doc", "content": "first content"}
        first = client.post("/v1/documents", json=body, headers=auth_headers)
        second = client.post("/v1/documents", json=body, headers=auth_headers)

        assert first.status_code == 200
        assert second.status_code == 400

    def test_document_tenant_isolation(self, client, auth_headers):
        tenant_b = TenantInfo(
            tenant_id="tenant-b",
            roles=[Role.ADMIN, Role.WRITE, Role.READ],
            subject="tenant-b-user",
        )
        register_api_key("tenant-b-key", tenant_b)
        tenant_b_headers = {"X-API-Key": "tenant-b-key"}

        client.post(
            "/v1/documents",
            json={"doc_id": "tenant-a-doc", "content": "private fraud investigation"},
            headers=auth_headers,
        )

        search_b = client.post(
            "/v1/documents/search",
            json={"query": "fraud"},
            headers=tenant_b_headers,
        )
        get_b = client.get("/v1/documents/tenant-a-doc", headers=tenant_b_headers)

        assert search_b.status_code == 200
        assert search_b.json()["count"] == 0
        assert get_b.status_code == 404

    def test_document_ingest_requires_write_role(self, client, read_only_headers):
        resp = client.post(
            "/v1/documents",
            json={"doc_id": "read-only-doc", "content": "cannot write"},
            headers=read_only_headers,
        )

        assert resp.status_code == 403


# =============================================================================
# Key Management
# =============================================================================


class TestKeyManagement:
    def test_list_keys_empty(self, client, auth_headers):
        resp = client.get("/v1/keys", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 0
        assert data["keys"] == []

    def test_list_keys_after_create(self, client, auth_headers):
        from encrypted_ir.api.routes.keys import _get_key_manager

        km = _get_key_manager("test-tenant-001")
        km.create_key("deterministic", description="test key")

        resp = client.get("/v1/keys", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        assert data["keys"][0]["key_type"] == "deterministic"
        assert data["keys"][0]["active"] is True

    def test_rotate_key_success(self, client, auth_headers):
        from encrypted_ir.api.routes.keys import _get_key_manager

        km = _get_key_manager("test-tenant-001")
        key_id = km.create_key("searchable")

        resp = client.post(
            "/v1/keys/rotate",
            json={"key_id": key_id},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["old_key_id"] == key_id
        assert data["new_key_id"] != key_id

    def test_rotate_nonexistent_key(self, client, auth_headers):
        resp = client.post(
            "/v1/keys/rotate",
            json={"key_id": "nonexistent-key"},
            headers=auth_headers,
        )
        assert resp.status_code == 404


# =============================================================================
# Rate Limiting
# =============================================================================


class TestRateLimiting:
    def test_rate_limit_exceeded(self, client, auth_headers):
        # Set a very low rate limit
        limiter = RateLimiter(
            limits={"encrypt": RateLimitConfig(max_requests=2, window_seconds=60)}
        )
        set_rate_limiter(limiter)

        # First two should succeed
        for _ in range(2):
            resp = client.post(
                "/v1/encrypt",
                json={"plaintext": "test"},
                headers=auth_headers,
            )
            assert resp.status_code == 200

        # Third should be rate limited
        resp = client.post(
            "/v1/encrypt",
            json={"plaintext": "test"},
            headers=auth_headers,
        )
        assert resp.status_code == 429
        assert "Retry-After" in resp.headers

    def test_rate_limit_different_tenants_independent(self, client):
        limiter = RateLimiter(
            limits={"encrypt": RateLimitConfig(max_requests=1, window_seconds=60)}
        )
        set_rate_limiter(limiter)

        # Tenant 1
        t1 = TenantInfo(tenant_id="tenant-1", roles=[Role.WRITE])
        register_api_key("key-t1", t1)

        # Tenant 2
        t2 = TenantInfo(tenant_id="tenant-2", roles=[Role.WRITE])
        register_api_key("key-t2", t2)

        # Tenant 1 first request
        resp1 = client.post(
            "/v1/encrypt",
            json={"plaintext": "test"},
            headers={"X-API-Key": "key-t1"},
        )
        assert resp1.status_code == 200

        # Tenant 2 first request (should succeed - different tenant)
        resp2 = client.post(
            "/v1/encrypt",
            json={"plaintext": "test"},
            headers={"X-API-Key": "key-t2"},
        )
        assert resp2.status_code == 200

        # Tenant 1 second request (should be rate limited)
        resp3 = client.post(
            "/v1/encrypt",
            json={"plaintext": "test"},
            headers={"X-API-Key": "key-t1"},
        )
        assert resp3.status_code == 429


# =============================================================================
# Error Handling
# =============================================================================


class TestErrorHandling:
    def test_validation_error_format(self, client, auth_headers):
        resp = client.post(
            "/v1/encrypt",
            json={"plaintext": "", "algorithm": "aes-siv"},  # empty plaintext
            headers=auth_headers,
        )
        assert resp.status_code == 422
        data = resp.json()
        assert data["error"] == "validation_error"
        assert len(data["details"]) > 0

    def test_invalid_json_body(self, client, auth_headers):
        resp = client.post(
            "/v1/encrypt",
            content=b"not-json",
            headers={**auth_headers, "Content-Type": "application/json"},
        )
        assert resp.status_code == 422

    def test_missing_required_field(self, client, auth_headers):
        resp = client.post(
            "/v1/encrypt",
            json={},
            headers=auth_headers,
        )
        assert resp.status_code == 422

    def test_not_found_error_format(self, client, auth_headers):
        resp = client.post(
            "/v1/keys/rotate",
            json={"key_id": "does-not-exist"},
            headers=auth_headers,
        )
        assert resp.status_code == 404
        data = resp.json()
        assert data["error"] == "not_found"

    def test_403_error_has_detail(self, client, read_only_headers):
        resp = client.post(
            "/v1/encrypt",
            json={"plaintext": "test"},
            headers=read_only_headers,
        )
        assert resp.status_code == 403
        data = resp.json()
        assert "detail" in data


# =============================================================================
# Request Tracing
# =============================================================================


class TestRequestTracing:
    def test_response_includes_request_id(self, client, auth_headers):
        resp = client.post(
            "/v1/encrypt",
            json={"plaintext": "test"},
            headers=auth_headers,
        )
        assert "x-request-id" in resp.headers

    def test_custom_request_id_preserved(self, client, auth_headers):
        custom_id = "trace-abc-123"
        resp = client.post(
            "/v1/encrypt",
            json={"plaintext": "test"},
            headers={**auth_headers, "X-Request-ID": custom_id},
        )
        assert resp.headers["x-request-id"] == custom_id
        assert resp.json()["request_id"] == custom_id

    def test_response_time_header(self, client):
        resp = client.get("/health")
        assert "x-response-time-ms" in resp.headers
        latency = float(resp.headers["x-response-time-ms"])
        assert latency >= 0


# =============================================================================
# Tenant Isolation
# =============================================================================


class TestTenantIsolation:
    def test_different_tenants_different_ciphers(self, client):
        t1 = TenantInfo(tenant_id="iso-tenant-1", roles=[Role.WRITE])
        register_api_key("iso-key-1", t1)

        t2 = TenantInfo(tenant_id="iso-tenant-2", roles=[Role.WRITE])
        register_api_key("iso-key-2", t2)

        # Encrypt with tenant 1
        enc1 = client.post(
            "/v1/encrypt",
            json={"plaintext": "same-data"},
            headers={"X-API-Key": "iso-key-1"},
        )
        # Encrypt with tenant 2
        enc2 = client.post(
            "/v1/encrypt",
            json={"plaintext": "same-data"},
            headers={"X-API-Key": "iso-key-2"},
        )

        # Different tenants should produce different ciphertexts (different keys)
        assert enc1.json()["ciphertext"] != enc2.json()["ciphertext"]

    def test_tenant_cannot_decrypt_other_tenant_data(self, client):
        t1 = TenantInfo(tenant_id="cross-tenant-1", roles=[Role.WRITE, Role.READ])
        register_api_key("cross-key-1", t1)

        t2 = TenantInfo(tenant_id="cross-tenant-2", roles=[Role.WRITE, Role.READ])
        register_api_key("cross-key-2", t2)

        # Encrypt with tenant 1
        enc = client.post(
            "/v1/encrypt",
            json={"plaintext": "secret"},
            headers={"X-API-Key": "cross-key-1"},
        )
        ct = enc.json()["ciphertext"]

        # Try to decrypt with tenant 2
        dec = client.post(
            "/v1/decrypt",
            json={"ciphertext": ct, "algorithm": "aes-siv"},
            headers={"X-API-Key": "cross-key-2"},
        )
        # Should fail (different key)
        assert dec.status_code in (400, 500)


# =============================================================================
# OpenAPI / Docs
# =============================================================================


class TestOpenAPI:
    def test_openapi_spec_available(self, client):
        resp = client.get("/openapi.json")
        assert resp.status_code == 200
        spec = resp.json()
        assert spec["info"]["title"] == "Encrypted Information Retrieval API"
        assert spec["info"]["version"] == "1.0.0"

    def test_docs_available(self, client):
        resp = client.get("/docs")
        assert resp.status_code == 200

    def test_openapi_has_all_endpoints(self, client):
        resp = client.get("/openapi.json")
        paths = resp.json()["paths"]
        expected_paths = [
            "/v1/encrypt",
            "/v1/decrypt",
            "/v1/search/equality",
            "/v1/search/range",
            "/v1/search/keyword",
            "/v1/keys/rotate",
            "/v1/keys",
            "/health",
            "/metrics",
        ]
        for path in expected_paths:
            assert path in paths, f"Missing path: {path}"
