"""Data encryption/decryption endpoints."""

from __future__ import annotations

import base64
from typing import TypeAlias, cast

from fastapi import APIRouter, Depends, Request

from encrypted_ir.deterministic import DeterministicEncryption
from encrypted_ir.searchable import SearchableEncryption

from ..dependencies.auth import Role, TenantInfo, require_role
from ..dependencies.rate_limiter import RateLimiter, get_rate_limiter
from ..models.requests import DecryptRequest, EncryptRequest
from ..models.responses import DecryptResponse, EncryptResponse

router = APIRouter(prefix="/v1", tags=["data"])

CipherInstance: TypeAlias = DeterministicEncryption | SearchableEncryption

# Per-tenant cipher instances (in production, keys come from KeyManager/KMS)
_tenant_ciphers: dict[str, CipherInstance] = {}


def _get_cipher(tenant_id: str, algorithm: str) -> CipherInstance:
    """Get or create a cipher instance for a tenant."""
    key = f"{tenant_id}:{algorithm}"
    if key not in _tenant_ciphers:
        if algorithm == "aes-siv":
            _tenant_ciphers[key] = DeterministicEncryption()
        else:
            _tenant_ciphers[key] = SearchableEncryption()
    return _tenant_ciphers[key]


def reset_ciphers() -> None:
    """Reset all cached cipher instances (for testing)."""
    _tenant_ciphers.clear()


@router.post(
    "/encrypt",
    response_model=EncryptResponse,
    summary="Encrypt plaintext data (compatibility demo)",
    description="Compatibility/demo endpoint using in-memory tenant ciphers. "
    "For durable encrypted retrieval, use /v1/documents.",
)
async def encrypt(
    body: EncryptRequest,
    request: Request,
    tenant: TenantInfo = Depends(require_role(Role.WRITE, Role.ADMIN)),
    rate_limiter: RateLimiter = Depends(get_rate_limiter),
) -> EncryptResponse:
    rate_limiter.check_limit(tenant.tenant_id, "encrypt")

    cipher = _get_cipher(tenant.tenant_id, body.algorithm)

    if body.algorithm == "aes-siv":
        deterministic_cipher = cast(DeterministicEncryption, cipher)
        ciphertext_bytes = deterministic_cipher.encrypt(body.plaintext)
        ciphertext_b64 = base64.b64encode(ciphertext_bytes).decode("ascii")
    else:
        searchable_cipher = cast(SearchableEncryption, cipher)
        encrypted_doc, _ = searchable_cipher.encrypt_document(body.plaintext)
        ciphertext_b64 = base64.b64encode(encrypted_doc).decode("ascii")

    return EncryptResponse(
        ciphertext=ciphertext_b64,
        algorithm=body.algorithm,
        request_id=request.state.request_id,
    )


@router.post(
    "/decrypt",
    response_model=DecryptResponse,
    summary="Decrypt ciphertext (compatibility demo)",
    description="Compatibility/demo endpoint using in-memory tenant ciphers. "
    "For durable encrypted retrieval, use /v1/documents/{doc_id}.",
)
async def decrypt(
    body: DecryptRequest,
    request: Request,
    tenant: TenantInfo = Depends(require_role(Role.READ, Role.WRITE, Role.ADMIN)),
    rate_limiter: RateLimiter = Depends(get_rate_limiter),
) -> DecryptResponse:
    rate_limiter.check_limit(tenant.tenant_id, "decrypt")

    cipher = _get_cipher(tenant.tenant_id, body.algorithm)
    ciphertext_bytes = base64.b64decode(body.ciphertext)

    if body.algorithm == "aes-siv":
        deterministic_cipher = cast(DeterministicEncryption, cipher)
        plaintext_bytes = deterministic_cipher.decrypt(ciphertext_bytes)
    else:
        searchable_cipher = cast(SearchableEncryption, cipher)
        plaintext_bytes = searchable_cipher.decrypt_document(ciphertext_bytes)

    return DecryptResponse(
        plaintext=plaintext_bytes.decode("utf-8"),
        algorithm=body.algorithm,
        request_id=request.state.request_id,
    )
