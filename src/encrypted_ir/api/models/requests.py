"""Pydantic request models for the encrypted IR API."""

from __future__ import annotations

import json
from typing import Annotated, Any

from pydantic import BaseModel, Field, StringConstraints, field_validator

# Letters, digits, '.', '_' and '-'; not starting with '.', so "." and ".." are rejected
# (HTTP clients normalize them away in URL paths).
DOC_ID_PATTERN = r"^[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$"
MAX_KEYWORDS = 256
MAX_KEYWORD_LENGTH = 128
MAX_METADATA_KEYS = 32
MAX_METADATA_BYTES = 16 * 1024

Keyword = Annotated[str, StringConstraints(min_length=1, max_length=MAX_KEYWORD_LENGTH)]


class DocumentIngestRequest(BaseModel):
    """Request to encrypt, index, and persist a document."""

    doc_id: str = Field(
        ...,
        pattern=DOC_ID_PATTERN,
        description="Document identifier: 1-128 of A-Z a-z 0-9 . _ -, not starting with '.'",
    )
    content: str = Field(..., min_length=1, max_length=10_000_000, description="Document text")
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            f"Caller-provided metadata stored with the encrypted document: at most "
            f"{MAX_METADATA_KEYS} keys and {MAX_METADATA_BYTES} bytes as JSON"
        ),
    )
    keywords: list[Keyword] | None = Field(
        default=None,
        max_length=MAX_KEYWORDS,
        description=(
            "Optional explicit keywords (at most 256, each 1-128 characters). If omitted, "
            "keywords are extracted from content."
        ),
    )

    @field_validator("metadata")
    @classmethod
    def validate_metadata_size(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(value) > MAX_METADATA_KEYS:
            raise ValueError(f"metadata may have at most {MAX_METADATA_KEYS} keys")
        size = len(json.dumps(value, separators=(",", ":"), default=str).encode("utf-8"))
        if size > MAX_METADATA_BYTES:
            raise ValueError(f"metadata may be at most {MAX_METADATA_BYTES} bytes as JSON")
        return value


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
