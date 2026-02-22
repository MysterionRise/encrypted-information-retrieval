"""Pydantic request models for the encrypted IR API."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field, field_validator


class EncryptRequest(BaseModel):
    """Request to encrypt plaintext data."""

    plaintext: str = Field(..., min_length=1, max_length=10_000_000, description="Data to encrypt")
    algorithm: str = Field(
        default="aes-siv",
        description="Encryption algorithm (aes-siv, aes-gcm)",
    )

    @field_validator("algorithm")
    @classmethod
    def validate_algorithm(cls, v: str) -> str:
        allowed = {"aes-siv", "aes-gcm"}
        if v not in allowed:
            raise ValueError(f"Algorithm must be one of: {', '.join(sorted(allowed))}")
        return v


class DecryptRequest(BaseModel):
    """Request to decrypt ciphertext."""

    ciphertext: str = Field(..., min_length=1, description="Base64-encoded ciphertext to decrypt")
    algorithm: str = Field(
        default="aes-siv",
        description="Encryption algorithm used (aes-siv, aes-gcm)",
    )

    @field_validator("algorithm")
    @classmethod
    def validate_algorithm(cls, v: str) -> str:
        allowed = {"aes-siv", "aes-gcm"}
        if v not in allowed:
            raise ValueError(f"Algorithm must be one of: {', '.join(sorted(allowed))}")
        return v


class EqualitySearchRequest(BaseModel):
    """Request for blind index equality search."""

    value: str = Field(..., min_length=1, description="Value to search for")
    field_name: str = Field(..., min_length=1, max_length=255, description="Field to search in")
    index_map: dict[str, str] = Field(..., description="Mapping of blind index -> record ID")
    output_length: int = Field(default=16, ge=8, le=64, description="Blind index output length")
    case_sensitive: bool = Field(default=False, description="Case-sensitive matching")


class RangeSearchRequest(BaseModel):
    """Request for ORE range query."""

    encrypted_values: list[str] = Field(
        ..., min_length=1, description="List of base64-encoded ORE ciphertexts"
    )
    min_value: Optional[int] = Field(default=None, ge=0, description="Minimum value (inclusive)")
    max_value: Optional[int] = Field(default=None, ge=0, description="Maximum value (inclusive)")

    @field_validator("encrypted_values")
    @classmethod
    def validate_not_empty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("encrypted_values must not be empty")
        return v


class KeywordSearchRequest(BaseModel):
    """Request for SSE keyword search."""

    keyword: str = Field(..., min_length=1, max_length=1000, description="Keyword to search for")
    document_tokens: dict[str, list[str]] = Field(
        ..., description="Mapping of document_id -> list of search tokens"
    )


class KeyRotateRequest(BaseModel):
    """Request to rotate a key."""

    key_id: str = Field(..., min_length=1, description="ID of the key to rotate")
