"""API tests for the durable encrypted document routes.

Tests cover:
- Health check and metrics endpoints
- Authentication (dev JWT, dev API key, missing or malformed credentials)
- Authorization (role enforcement)
- Durable document ingest, search, get and RAG retrieval
- Tenant isolation on every document route
- Rate limiting
- Error handling (validation, not found, forbidden)
- Request ID tracing
- OpenAPI surface, including the absence of the removed demo routes
"""

from __future__ import annotations

import base64
import json

import jwt
import pytest

from encrypted_ir import __version__
from encrypted_ir.api.dependencies.rate_limiter import (
    RateLimitConfig,
    RateLimiter,
    set_rate_limiter,
)

REMOVED_DEMO_PATHS = (
    "/v1/encrypt",
    "/v1/decrypt",
    "/v1/search/equality",
    "/v1/search/range",
    "/v1/search/keyword",
    "/v1/keys",
    "/v1/keys/rotate",
)


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _make_unsigned_jwt(payload: dict) -> str:
    """Create an unsigned JWT to verify alg:none tokens are rejected."""
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(
        b"="
    )
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=")
    sig = base64.urlsafe_b64encode(b"test-sig").rstrip(b"=")
    return f"{header.decode()}.{body.decode()}.{sig.decode()}"


def _ingest(client, headers, doc_id: str, content: str, **extra) -> None:
    resp = client.post(
        "/v1/documents",
        json={"doc_id": doc_id, "content": content, **extra},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text


SEARCH_BODY = {"query": "fraud"}


# =============================================================================
# Health & Metrics (no auth required)
# =============================================================================


class TestHealthCheck:
    def test_health_returns_200(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["version"] == __version__
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
        assert data["request_count"] >= 2


# =============================================================================
# Authentication
# =============================================================================


class TestAuth:
    def test_missing_auth_returns_401(self, client):
        resp = client.post("/v1/documents/search", json=SEARCH_BODY)
        assert resp.status_code == 401

    def test_invalid_api_key_returns_401(self, client):
        resp = client.post(
            "/v1/documents/search", json=SEARCH_BODY, headers={"X-API-Key": "bad-key"}
        )
        assert resp.status_code == 401

    def test_dev_api_key_succeeds(self, client, app):
        resp = client.post(
            "/v1/documents/search",
            json=SEARCH_BODY,
            headers={"X-API-Key": app.state.auth_config.dev_api_key},
        )
        assert resp.status_code == 200

    def test_jwt_auth_succeeds(self, client, make_token):
        token = make_token("jwt-tenant", ["write"])
        resp = client.post(
            "/v1/documents",
            json={"doc_id": "jwt-doc", "content": "written with a dev JWT"},
            headers=_bearer(token),
        )
        assert resp.status_code == 200
        assert resp.json()["tenant_id"] == "jwt-tenant"

    def test_jwt_missing_tenant_id_returns_401(self, client, make_token):
        token = make_token(None, ["read"])
        resp = client.post("/v1/documents/search", json=SEARCH_BODY, headers=_bearer(token))
        assert resp.status_code == 401

    def test_jwt_with_wrong_secret_returns_401(self, client):
        token = jwt.encode(
            {"tenant_id": "jwt-tenant", "roles": ["read"], "sub": "user1"},
            "a-different-secret-that-is-long-enough",
            algorithm="HS256",
        )
        resp = client.post("/v1/documents/search", json=SEARCH_BODY, headers=_bearer(token))
        assert resp.status_code == 401

    def test_unsigned_jwt_returns_401(self, client):
        token = _make_unsigned_jwt({"tenant_id": "jwt-tenant", "roles": ["write"]})
        resp = client.post("/v1/documents/search", json=SEARCH_BODY, headers=_bearer(token))
        assert resp.status_code == 401

    def test_malformed_jwt_returns_401(self, client):
        resp = client.post(
            "/v1/documents/search", json=SEARCH_BODY, headers=_bearer("not.a.valid.jwt")
        )
        assert resp.status_code == 401


# =============================================================================
# Authorization (RBAC)
# =============================================================================


class TestAuthorization:
    def test_read_only_cannot_ingest(self, client, read_only_headers):
        resp = client.post(
            "/v1/documents",
            json={"doc_id": "read-only-doc", "content": "cannot write"},
            headers=read_only_headers,
        )
        assert resp.status_code == 403

    def test_read_only_can_search_get_and_retrieve(self, client, auth_headers, read_only_headers):
        _ingest(client, auth_headers, "shared-doc", "fraud review notes")

        search = client.post("/v1/documents/search", json=SEARCH_BODY, headers=read_only_headers)
        get_resp = client.get("/v1/documents/shared-doc", headers=read_only_headers)
        rag = client.post(
            "/v1/rag/retrieve",
            json={"query": "fraud", "include_plaintext": True},
            headers=read_only_headers,
        )

        assert search.status_code == 200
        assert search.json()["count"] == 1
        assert get_resp.status_code == 200
        assert get_resp.json()["plaintext"] == "fraud review notes"
        assert rag.status_code == 200
        assert rag.json()["candidates"][0]["doc_id"] == "shared-doc"


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
        _ingest(
            client,
            auth_headers,
            "aml-note-1",
            "AML investigation notes mention suspicious transfer patterns",
            metadata={"case": "aml"},
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


class TestTenantIsolation:
    """Another tenant must not see, fetch or retrieve tenant A's documents."""

    @pytest.fixture()
    def tenant_b_headers(self, make_token):
        return _bearer(make_token("tenant-b", ["admin", "write", "read"]))

    @pytest.fixture(autouse=True)
    def _tenant_a_document(self, client, auth_headers):
        _ingest(client, auth_headers, "tenant-a-doc", "private fraud investigation")

    def test_search_does_not_return_other_tenant_documents(self, client, tenant_b_headers):
        resp = client.post("/v1/documents/search", json=SEARCH_BODY, headers=tenant_b_headers)
        assert resp.status_code == 200
        assert resp.json()["count"] == 0

    def test_get_returns_404_for_other_tenant_document(self, client, tenant_b_headers):
        resp = client.get("/v1/documents/tenant-a-doc", headers=tenant_b_headers)
        assert resp.status_code == 404

    def test_rag_does_not_return_other_tenant_documents(self, client, tenant_b_headers):
        resp = client.post(
            "/v1/rag/retrieve",
            json={"query": "fraud", "include_plaintext": True},
            headers=tenant_b_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["count"] == 0

    def test_same_doc_id_is_independent_per_tenant(self, client, tenant_b_headers):
        _ingest(client, tenant_b_headers, "tenant-a-doc", "tenant b owns this copy")
        resp = client.get("/v1/documents/tenant-a-doc", headers=tenant_b_headers)
        assert resp.status_code == 200
        assert resp.json()["plaintext"] == "tenant b owns this copy"


# =============================================================================
# Rate Limiting
# =============================================================================


class TestRateLimiting:
    def test_rate_limit_exceeded(self, client, auth_headers):
        set_rate_limiter(
            RateLimiter(
                limits={"document_search": RateLimitConfig(max_requests=2, window_seconds=60)}
            )
        )

        for _ in range(2):
            resp = client.post("/v1/documents/search", json=SEARCH_BODY, headers=auth_headers)
            assert resp.status_code == 200

        resp = client.post("/v1/documents/search", json=SEARCH_BODY, headers=auth_headers)
        assert resp.status_code == 429
        assert "Retry-After" in resp.headers

    def test_rate_limit_different_tenants_independent(self, client, make_token):
        set_rate_limiter(
            RateLimiter(
                limits={"document_search": RateLimitConfig(max_requests=1, window_seconds=60)}
            )
        )
        tenant_1 = _bearer(make_token("tenant-1", ["read"]))
        tenant_2 = _bearer(make_token("tenant-2", ["read"]))

        first_1 = client.post("/v1/documents/search", json=SEARCH_BODY, headers=tenant_1)
        first_2 = client.post("/v1/documents/search", json=SEARCH_BODY, headers=tenant_2)
        second_1 = client.post("/v1/documents/search", json=SEARCH_BODY, headers=tenant_1)

        assert first_1.status_code == 200
        assert first_2.status_code == 200
        assert second_1.status_code == 429


# =============================================================================
# Error Handling
# =============================================================================


class TestErrorHandling:
    def test_validation_error_format(self, client, auth_headers):
        resp = client.post(
            "/v1/documents",
            json={"doc_id": "empty-doc", "content": ""},
            headers=auth_headers,
        )
        assert resp.status_code == 422
        data = resp.json()
        assert data["error"] == "validation_error"
        assert len(data["details"]) > 0

    def test_invalid_json_body(self, client, auth_headers):
        resp = client.post(
            "/v1/documents",
            content=b"not-json",
            headers={**auth_headers, "Content-Type": "application/json"},
        )
        assert resp.status_code == 422

    def test_missing_required_field(self, client, auth_headers):
        resp = client.post("/v1/documents", json={}, headers=auth_headers)
        assert resp.status_code == 422

    def test_not_found_error_format(self, client, auth_headers):
        resp = client.get("/v1/documents/does-not-exist", headers=auth_headers)
        assert resp.status_code == 404
        assert resp.json()["error"] == "not_found"

    def test_403_error_has_detail(self, client, read_only_headers):
        resp = client.post(
            "/v1/documents",
            json={"doc_id": "forbidden", "content": "test"},
            headers=read_only_headers,
        )
        assert resp.status_code == 403
        assert "detail" in resp.json()


# =============================================================================
# Request Tracing
# =============================================================================


class TestRequestTracing:
    def test_response_includes_request_id(self, client, auth_headers):
        resp = client.post("/v1/documents/search", json=SEARCH_BODY, headers=auth_headers)
        assert "x-request-id" in resp.headers

    def test_custom_request_id_preserved(self, client, auth_headers):
        custom_id = "trace-abc-123"
        resp = client.post(
            "/v1/documents/search",
            json=SEARCH_BODY,
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
# OpenAPI / Docs
# =============================================================================


class TestOpenAPI:
    def test_openapi_spec_available(self, client):
        resp = client.get("/openapi.json")
        assert resp.status_code == 200
        spec = resp.json()
        assert spec["info"]["title"] == "Encrypted Information Retrieval API"
        assert spec["info"]["version"] == __version__

    def test_docs_available(self, client):
        resp = client.get("/docs")
        assert resp.status_code == 200

    def test_openapi_lists_exactly_the_durable_routes(self, client):
        paths = client.get("/openapi.json").json()["paths"]
        assert set(paths) == {
            "/v1/documents",
            "/v1/documents/search",
            "/v1/documents/{doc_id}",
            "/v1/rag/retrieve",
            "/health",
            "/ready",
            "/metrics",
        }

    @pytest.mark.parametrize("path", REMOVED_DEMO_PATHS)
    def test_removed_demo_routes_return_404(self, client, auth_headers, path):
        assert client.post(path, json={}, headers=auth_headers).status_code == 404
        assert client.get(path, headers=auth_headers).status_code == 404
