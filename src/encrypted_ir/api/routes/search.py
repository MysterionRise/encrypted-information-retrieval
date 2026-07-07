"""Search endpoints for equality, range, and keyword queries."""

from __future__ import annotations

import base64

from fastapi import APIRouter, Depends, Request

from encrypted_ir.blind_index import BlindIndexConfig, BlindIndexGenerator
from encrypted_ir.ore import ORE
from encrypted_ir.searchable import SearchableEncryption

from ..dependencies.auth import Role, TenantInfo, require_role
from ..dependencies.rate_limiter import RateLimiter, get_rate_limiter
from ..models.requests import (
    EqualitySearchRequest,
    KeywordSearchRequest,
    RangeSearchRequest,
)
from ..models.responses import SearchResponse

router = APIRouter(prefix="/v1/search", tags=["search"])

# Per-tenant crypto instances (in production, keys from KeyManager)
_tenant_blind_index: dict[str, BlindIndexGenerator] = {}
_tenant_ore: dict[str, ORE] = {}
_tenant_sse: dict[str, SearchableEncryption] = {}


def _get_blind_index(tenant_id: str) -> BlindIndexGenerator:
    if tenant_id not in _tenant_blind_index:
        _tenant_blind_index[tenant_id] = BlindIndexGenerator(tenant_id)
    return _tenant_blind_index[tenant_id]


def _get_ore(tenant_id: str) -> ORE:
    if tenant_id not in _tenant_ore:
        _tenant_ore[tenant_id] = ORE()
    return _tenant_ore[tenant_id]


def _get_sse(tenant_id: str) -> SearchableEncryption:
    if tenant_id not in _tenant_sse:
        _tenant_sse[tenant_id] = SearchableEncryption()
    return _tenant_sse[tenant_id]


def reset_search_state() -> None:
    """Reset all per-tenant search state (for testing)."""
    _tenant_blind_index.clear()
    _tenant_ore.clear()
    _tenant_sse.clear()


@router.post(
    "/equality",
    response_model=SearchResponse,
    summary="Blind index equality search (compatibility demo)",
    description="Compatibility/demo search over a request-supplied index map. "
    "The durable document workflow is available under /v1/documents/search.",
)
async def search_equality(
    body: EqualitySearchRequest,
    request: Request,
    tenant: TenantInfo = Depends(require_role(Role.READ, Role.WRITE, Role.ADMIN)),
    rate_limiter: RateLimiter = Depends(get_rate_limiter),
) -> SearchResponse:
    rate_limiter.check_limit(tenant.tenant_id, "equality_search")

    generator = _get_blind_index(tenant.tenant_id)
    config = BlindIndexConfig(
        field_name=body.field_name,
        output_length=body.output_length,
        case_sensitive=body.case_sensitive,
    )
    query_index = generator.create_index(body.value, config)

    matches = []
    if query_index in body.index_map:
        matches.append(body.index_map[query_index])

    return SearchResponse(
        matches=matches,
        count=len(matches),
        request_id=request.state.request_id,
    )


@router.post(
    "/range",
    response_model=SearchResponse,
    summary="ORE range query (prototype demo)",
    description="Prototype range query over request-supplied ORE ciphertexts. "
    "Custom ORE requires review before production use.",
)
async def search_range(
    body: RangeSearchRequest,
    request: Request,
    tenant: TenantInfo = Depends(require_role(Role.READ, Role.WRITE, Role.ADMIN)),
    rate_limiter: RateLimiter = Depends(get_rate_limiter),
) -> SearchResponse:
    rate_limiter.check_limit(tenant.tenant_id, "range_search")

    ore = _get_ore(tenant.tenant_id)

    # Decode encrypted values
    encrypted_values = [base64.b64decode(v) for v in body.encrypted_values]

    # Encrypt range bounds
    min_ct = ore.encrypt_int(body.min_value) if body.min_value is not None else None
    max_ct = ore.encrypt_int(body.max_value) if body.max_value is not None else None

    # Perform range query
    results = ore.range_query(encrypted_values, min_val=min_ct, max_val=max_ct)

    # Encode results back to base64
    matches = [base64.b64encode(r).decode("ascii") for r in results]

    return SearchResponse(
        matches=matches,
        count=len(matches),
        request_id=request.state.request_id,
    )


@router.post(
    "/keyword",
    response_model=SearchResponse,
    summary="SSE keyword search (compatibility demo)",
    description="Compatibility/demo search over request-supplied keyword tokens. "
    "Use /v1/documents/search for persisted encrypted document retrieval.",
)
async def search_keyword(
    body: KeywordSearchRequest,
    request: Request,
    tenant: TenantInfo = Depends(require_role(Role.READ, Role.WRITE, Role.ADMIN)),
    rate_limiter: RateLimiter = Depends(get_rate_limiter),
) -> SearchResponse:
    rate_limiter.check_limit(tenant.tenant_id, "keyword_search")

    sse = _get_sse(tenant.tenant_id)
    query_token = sse.generate_search_query(body.keyword)

    matches = []
    for doc_id, tokens in body.document_tokens.items():
        if query_token in tokens:
            matches.append(doc_id)

    return SearchResponse(
        matches=matches,
        count=len(matches),
        request_id=request.state.request_id,
    )
