"""Pydantic response models for the encrypted IR API."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class EncryptResponse(BaseModel):
    """Response containing encrypted data."""

    ciphertext: str = Field(..., description="Base64-encoded ciphertext")
    algorithm: str = Field(..., description="Encryption algorithm used")
    request_id: str = Field(..., description="Request trace ID")


class DecryptResponse(BaseModel):
    """Response containing decrypted data."""

    plaintext: str = Field(..., description="Decrypted plaintext")
    algorithm: str = Field(..., description="Encryption algorithm used")
    request_id: str = Field(..., description="Request trace ID")


class SearchResult(BaseModel):
    """A single search result."""

    record_id: str = Field(..., description="ID of the matching record")


class SearchResponse(BaseModel):
    """Response for search operations."""

    matches: list[str] = Field(default_factory=list, description="Matching record IDs")
    count: int = Field(..., description="Number of matches")
    request_id: str = Field(..., description="Request trace ID")


class KeyInfoResponse(BaseModel):
    """Information about a single key."""

    key_id: str = Field(..., description="Key identifier")
    key_type: str = Field(..., description="Key type")
    created_at: str = Field(..., description="Creation timestamp (ISO 8601)")
    active: bool = Field(..., description="Whether key is active")
    needs_rotation: bool = Field(..., description="Whether key needs rotation")
    access_count: int = Field(..., description="Number of times accessed")


class KeyListResponse(BaseModel):
    """Response listing keys for a tenant."""

    keys: list[KeyInfoResponse] = Field(default_factory=list, description="List of keys")
    count: int = Field(..., description="Total number of keys")
    request_id: str = Field(..., description="Request trace ID")


class KeyRotateResponse(BaseModel):
    """Response after key rotation."""

    old_key_id: str = Field(..., description="Old key ID (now inactive)")
    new_key_id: str = Field(..., description="New key ID")
    request_id: str = Field(..., description="Request trace ID")


class DocumentIngestResponse(BaseModel):
    """Response after storing an encrypted document."""

    doc_id: str = Field(..., description="Document identifier")
    tenant_id: str = Field(..., description="Tenant that owns the document")
    algorithm: str = Field(..., description="Document encryption algorithm")
    key_id: str = Field(..., description="Encryption key ID used for the document")
    indexed_token_count: int = Field(..., description="Number of search tokens stored")
    request_id: str = Field(..., description="Request trace ID")


class DocumentMatch(BaseModel):
    """Search match for encrypted document retrieval."""

    doc_id: str = Field(..., description="Document identifier")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Stored metadata")
    score: int = Field(..., description="Number of matched keyword tokens")


class DocumentSearchResponse(BaseModel):
    """Response for durable encrypted document search."""

    matches: list[DocumentMatch] = Field(default_factory=list, description="Matching documents")
    count: int = Field(..., description="Number of matches")
    request_id: str = Field(..., description="Request trace ID")


class DocumentGetResponse(BaseModel):
    """Response containing one decrypted document."""

    doc_id: str = Field(..., description="Document identifier")
    tenant_id: str = Field(..., description="Tenant that owns the document")
    plaintext: str = Field(..., description="Decrypted document content")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Stored metadata")
    key_id: str = Field(..., description="Encryption key ID used for decryption")
    request_id: str = Field(..., description="Request trace ID")


class RagCandidate(BaseModel):
    """Candidate returned to a downstream RAG system."""

    doc_id: str = Field(..., description="Document identifier")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Stored metadata")
    score: int = Field(..., description="Keyword-token match score")
    plaintext: str | None = Field(
        default=None,
        description="Optional decrypted content for authorized RAG context assembly",
    )


class RagRetrieveResponse(BaseModel):
    """RAG-ready retrieval response."""

    candidates: list[RagCandidate] = Field(default_factory=list, description="Ranked candidates")
    count: int = Field(..., description="Number of candidates")
    request_id: str = Field(..., description="Request trace ID")


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = Field(..., description="Service status (healthy/degraded/unhealthy)")
    version: str = Field(..., description="API version")
    uptime_seconds: float = Field(..., description="Seconds since startup")


class MetricsResponse(BaseModel):
    """Prometheus-style metrics."""

    request_count: int = Field(default=0, description="Total requests served")
    error_count: int = Field(default=0, description="Total errors")
    active_tenants: int = Field(default=0, description="Number of active tenants")
    requests_by_endpoint: dict[str, int] = Field(
        default_factory=dict, description="Request counts per endpoint"
    )
    avg_latency_ms: float = Field(default=0.0, description="Average latency in ms")


class ReadinessResponse(BaseModel):
    """Readiness check response."""

    status: str = Field(..., description="ready or not_ready")
    checks: dict[str, Any] = Field(default_factory=dict, description="Readiness check details")


class ErrorDetail(BaseModel):
    """Detail about a specific validation error."""

    field: str = Field(..., description="Field name")
    message: str = Field(..., description="Error message")


class ErrorResponse(BaseModel):
    """Standard error response."""

    error: str = Field(..., description="Error type")
    message: str = Field(..., description="Human-readable error message")
    request_id: str = Field(..., description="Request trace ID")
    details: list[ErrorDetail] = Field(default_factory=list, description="Detailed field errors")
