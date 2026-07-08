"""Durable encrypted document and RAG retrieval endpoints."""

from __future__ import annotations

from contextlib import suppress
from typing import Any, cast

from fastapi import APIRouter, Depends, Request

from encrypted_ir.document_service import DocumentService

from ..dependencies.auth import Role, TenantInfo, require_role
from ..dependencies.rate_limiter import RateLimiter, get_rate_limiter
from ..models.requests import (
    DocumentIngestRequest,
    DocumentSearchRequest,
    RagRetrieveRequest,
)
from ..models.responses import (
    DocumentGetResponse,
    DocumentIngestResponse,
    DocumentMatch,
    DocumentSearchResponse,
    RagCandidate,
    RagRetrieveResponse,
)

router = APIRouter(tags=["documents"])


def _service(request: Request) -> DocumentService:
    service = getattr(request.app.state, "document_service", None)
    if service is None:
        raise RuntimeError("Document service is not configured")
    return cast(DocumentService, service)


def _actor(request: Request) -> str:
    return getattr(request.state, "actor", "unknown")


def _record_failure(
    request: Request,
    tenant: TenantInfo,
    event_type: str,
    exc: Exception,
    resource: str = "",
    details: dict[str, Any] | None = None,
) -> None:
    """Best-effort sanitized failure audit for authorized document workflows."""
    audit_details = {"error_type": exc.__class__.__name__, **(details or {})}
    with suppress(Exception):
        _service(request).record_audit_event(
            tenant_id=tenant.tenant_id,
            event_type=event_type,
            actor=_actor(request),
            success=False,
            resource=resource,
            details=audit_details,
            request_id=request.state.request_id,
        )


@router.post(
    "/v1/documents",
    response_model=DocumentIngestResponse,
    summary="Encrypt, index, and store a document",
    description=(
        "Durable portfolio workflow for regulated RAG retrieval. The API encrypts "
        "document content, stores search tokens, and persists tenant-scoped key metadata."
    ),
)
async def ingest_document(
    body: DocumentIngestRequest,
    request: Request,
    tenant: TenantInfo = Depends(require_role(Role.WRITE, Role.ADMIN)),
    rate_limiter: RateLimiter = Depends(get_rate_limiter),
) -> DocumentIngestResponse:
    rate_limiter.check_limit(tenant.tenant_id, "document_ingest")

    try:
        result = _service(request).ingest_document(
            tenant_id=tenant.tenant_id,
            doc_id=body.doc_id,
            content=body.content,
            metadata=body.metadata,
            keywords=set(body.keywords) if body.keywords is not None else None,
        )
    except Exception as exc:
        _record_failure(request, tenant, "document.encrypt", exc, resource=body.doc_id)
        raise
    _service(request).record_audit_event(
        tenant_id=tenant.tenant_id,
        event_type="document.encrypt",
        actor=_actor(request),
        success=True,
        resource=body.doc_id,
        details={"indexed_token_count": result["indexed_token_count"]},
        request_id=request.state.request_id,
    )
    return DocumentIngestResponse(**result, request_id=request.state.request_id)


@router.post(
    "/v1/documents/search",
    response_model=DocumentSearchResponse,
    summary="Search persisted encrypted documents",
    description=(
        "Search tenant-owned encrypted documents using deterministic keyword tokens. "
        "This endpoint is RAG-ready retrieval infrastructure; it does not call an LLM."
    ),
)
async def search_documents(
    body: DocumentSearchRequest,
    request: Request,
    tenant: TenantInfo = Depends(require_role(Role.READ, Role.WRITE, Role.ADMIN)),
    rate_limiter: RateLimiter = Depends(get_rate_limiter),
) -> DocumentSearchResponse:
    rate_limiter.check_limit(tenant.tenant_id, "document_search")

    try:
        matches = _service(request).search_documents(
            tenant_id=tenant.tenant_id,
            query=body.query,
            operator=body.operator,
            limit=body.limit,
        )
    except Exception as exc:
        _record_failure(
            request,
            tenant,
            "document.search",
            exc,
            details={"operator": body.operator, "limit": body.limit},
        )
        raise
    _service(request).record_audit_event(
        tenant_id=tenant.tenant_id,
        event_type="document.search",
        actor=_actor(request),
        success=True,
        details={"result_count": len(matches), "operator": body.operator, "limit": body.limit},
        request_id=request.state.request_id,
    )
    return DocumentSearchResponse(
        matches=[
            DocumentMatch(doc_id=m.doc_id, metadata=m.metadata, score=m.score) for m in matches
        ],
        count=len(matches),
        request_id=request.state.request_id,
    )


@router.get(
    "/v1/documents/{doc_id}",
    response_model=DocumentGetResponse,
    summary="Decrypt a stored document",
    description="Decrypt one authorized tenant-owned document by ID for retrieval pipelines.",
)
async def get_document(
    doc_id: str,
    request: Request,
    tenant: TenantInfo = Depends(require_role(Role.READ, Role.WRITE, Role.ADMIN)),
    rate_limiter: RateLimiter = Depends(get_rate_limiter),
) -> DocumentGetResponse:
    rate_limiter.check_limit(tenant.tenant_id, "document_get")

    try:
        record = _service(request).get_document(tenant.tenant_id, doc_id)
    except Exception as exc:
        _record_failure(request, tenant, "document.decrypt", exc, resource=doc_id)
        raise
    _service(request).record_audit_event(
        tenant_id=tenant.tenant_id,
        event_type="document.decrypt",
        actor=_actor(request),
        success=True,
        resource=doc_id,
        details={"metadata_keys": sorted(record.metadata.keys())},
        request_id=request.state.request_id,
    )
    return DocumentGetResponse(
        doc_id=record.doc_id,
        tenant_id=record.tenant_id,
        plaintext=record.plaintext,
        metadata=record.metadata,
        key_id=record.key_id,
        request_id=request.state.request_id,
    )


@router.post(
    "/v1/rag/retrieve",
    response_model=RagRetrieveResponse,
    summary="Retrieve encrypted-document candidates for RAG",
    description=(
        "Return ranked keyword-token candidates for a downstream RAG system. "
        "No embeddings or LLM calls are performed in this prototype workflow."
    ),
)
async def retrieve_for_rag(
    body: RagRetrieveRequest,
    request: Request,
    tenant: TenantInfo = Depends(require_role(Role.READ, Role.WRITE, Role.ADMIN)),
    rate_limiter: RateLimiter = Depends(get_rate_limiter),
) -> RagRetrieveResponse:
    rate_limiter.check_limit(tenant.tenant_id, "rag_retrieve")

    try:
        candidates = _service(request).retrieve_for_rag(
            tenant_id=tenant.tenant_id,
            query=body.query,
            top_k=body.top_k,
            include_plaintext=body.include_plaintext,
        )
    except Exception as exc:
        _record_failure(
            request,
            tenant,
            "rag.retrieve",
            exc,
            details={"top_k": body.top_k, "include_plaintext": body.include_plaintext},
        )
        raise
    _service(request).record_audit_event(
        tenant_id=tenant.tenant_id,
        event_type="rag.retrieve",
        actor=_actor(request),
        success=True,
        details={
            "result_count": len(candidates),
            "top_k": body.top_k,
            "include_plaintext": body.include_plaintext,
        },
        request_id=request.state.request_id,
    )
    return RagRetrieveResponse(
        candidates=[
            RagCandidate(
                doc_id=c.doc_id,
                metadata=c.metadata,
                score=c.score,
                plaintext=c.plaintext,
            )
            for c in candidates
        ],
        count=len(candidates),
        request_id=request.state.request_id,
    )
