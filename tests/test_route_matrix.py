"""Every durable route rejects unauthenticated and under-privileged callers and stays tenant-scoped.

The route list comes from the app itself, so a new ``/v1`` route without an entry in ``MATRIX``
fails ``test_every_durable_route_is_covered`` until its 401, 403 and cross-tenant cases exist.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import pytest
from fastapi.testclient import TestClient
from httpx import Response

from tests.conftest import bearer

OWNER = "tenant-a"
OTHER = "tenant-b"
ALL_ROLES = ["admin", "write", "read"]
DOC = {"doc_id": "doc-a", "content": "tenant a fraud memo", "metadata": {"owner": OWNER}}

Call = Callable[[TestClient, dict[str, str]], Response]


@dataclass(frozen=True)
class RouteCase:
    call: Call
    # A role that authenticates but is not allowed on this route.
    forbidden_role: str
    # Called with tenant B's response; tenant A's document must be untouched afterwards.
    check_cross_tenant: Callable[[Response], None]


def _no_matches(resp: Response) -> None:
    assert resp.status_code == 200
    assert resp.json()["matches"] == []


def _no_candidates(resp: Response) -> None:
    assert resp.status_code == 200
    assert resp.json()["candidates"] == []


def _not_found(resp: Response) -> None:
    assert resp.status_code == 404


def _separate_document(resp: Response) -> None:
    # Tenant B may use the same document ID; it is a different document, not a conflict.
    assert resp.status_code == 200
    assert resp.json()["tenant_id"] == OTHER


MATRIX: dict[tuple[str, str], RouteCase] = {
    ("POST", "/v1/documents"): RouteCase(
        call=lambda c, h: c.post(
            "/v1/documents", json={"doc_id": "doc-a", "content": "tenant b memo"}, headers=h
        ),
        forbidden_role="read",
        check_cross_tenant=_separate_document,
    ),
    ("POST", "/v1/documents/search"): RouteCase(
        call=lambda c, h: c.post("/v1/documents/search", json={"query": "fraud memo"}, headers=h),
        forbidden_role="auditor",
        check_cross_tenant=_no_matches,
    ),
    ("GET", "/v1/documents/{doc_id}"): RouteCase(
        call=lambda c, h: c.get("/v1/documents/doc-a", headers=h),
        forbidden_role="auditor",
        check_cross_tenant=_not_found,
    ),
    ("DELETE", "/v1/documents/{doc_id}"): RouteCase(
        call=lambda c, h: c.delete("/v1/documents/doc-a", headers=h),
        forbidden_role="read",
        check_cross_tenant=_not_found,
    ),
    ("POST", "/v1/rag/retrieve"): RouteCase(
        call=lambda c, h: c.post(
            "/v1/rag/retrieve", json={"query": "fraud memo", "include_plaintext": True}, headers=h
        ),
        forbidden_role="auditor",
        check_cross_tenant=_no_candidates,
    ),
}


def _durable_routes(app: Any) -> set[tuple[str, str]]:
    return {
        (method.upper(), path)
        for path, operations in app.openapi()["paths"].items()
        if path.startswith("/v1/")
        for method in operations
    }


@pytest.fixture()
def owner_headers(make_token) -> dict[str, str]:
    return bearer(make_token(OWNER, ALL_ROLES))


@pytest.fixture()
def seeded(client, owner_headers) -> TestClient:
    assert client.post("/v1/documents", json=DOC, headers=owner_headers).status_code == 200
    return client


def test_every_durable_route_is_covered(app):
    assert _durable_routes(app) == set(MATRIX)


@pytest.mark.parametrize("route", sorted(MATRIX), ids=lambda r: f"{r[0]} {r[1]}")
class TestEveryRoute:
    def test_unauthenticated_is_401(self, client, route):
        resp = MATRIX[route].call(client, {})
        assert resp.status_code == 401
        assert resp.json() == {"detail": "Not authenticated"}

    def test_bad_token_is_401(self, client, route):
        resp = MATRIX[route].call(client, bearer("not-a-jwt"))
        assert resp.status_code == 401

    def test_insufficient_role_is_403(self, client, make_token, route):
        resp = MATRIX[route].call(client, bearer(make_token(OWNER, [MATRIX[route].forbidden_role])))
        assert resp.status_code == 403

    def test_other_tenant_cannot_reach_tenant_a(self, seeded, make_token, owner_headers, route):
        resp = MATRIX[route].call(seeded, bearer(make_token(OTHER, ALL_ROLES)))

        MATRIX[route].check_cross_tenant(resp)
        owned = seeded.get("/v1/documents/doc-a", headers=owner_headers)
        assert owned.status_code == 200
        assert owned.json()["plaintext"] == DOC["content"]
        assert owned.json()["metadata"] == DOC["metadata"]
