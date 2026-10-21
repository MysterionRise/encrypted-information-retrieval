"""Pydantic request models for the encrypted IR API."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator


class DocumentIngestRequest(BaseModel):
    """Request to encrypt, index, and persist a document."""

    doc_id: str = Field(..., min_length=1, max_length=255, description="Document identifier")
    content: str = Field(..., min_length=1, max_length=10_000_000, description="Document text")
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Caller-provided metadata stored with the encrypted document",
    )
    keywords: list[str] | None = Field(
        default=None,
        description="Optional explicit keywords. If omitted, keywords are extracted from content.",
    )


class DocumentSearchRequest(BaseModel):
    """Request to retrieve documents by encrypted keyword tokens."""

    query: str = Field(..., min_length=1, max_length=1000, description="Keyword query")
    operator: str = Field(default="OR", description="Keyword operator: OR or AND")
    limit: int = Field(default=10, ge=1, le=100, description="Maximum result count")

    @field_validator("operator")
    @classmethod
    def validate_operator(cls, v: str) -> str:
        normalized = v.upper()
        if normalized not in {"OR", "AND"}:
            raise ValueError("operator must be OR or AND")
        return normalized


class RagRetrieveRequest(BaseModel):
    """Request for RAG-ready encrypted retrieval candidates."""

    query: str = Field(..., min_length=1, max_length=1000, description="Retrieval query")
    top_k: int = Field(default=5, ge=1, le=25, description="Maximum candidate count")
    include_plaintext: bool = Field(
        default=False,
        description="Include decrypted plaintext for authorized downstream RAG use",
    )
