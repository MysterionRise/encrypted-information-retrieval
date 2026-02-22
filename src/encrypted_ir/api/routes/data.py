"""Data encryption/decryption endpoints."""

from __future__ import annotations

import base64

from fastapi import APIRouter, Depends, Request

from encrypted_ir.deterministic import DeterministicEncryption
from encrypted_ir.searchable import SearchableEncryption

from ..dependencies.auth import Role, TenantInfo, require_role
from ..dependencies.rate_limiter import RateLimiter, get_rate_limiter
from ..models.requests import DecryptRequest, EncryptRequest
from ..models.responses import DecryptResponse, EncryptResponse

router = APIRouter(prefix="/v1", tags=["data"])

# Per-tenant cipher instances (in production, keys come from KeyManager/KMS)
_tenant_ciphers: dict[str, dict] = {}


def _get_cipher(tenant_id: str, algorithm: str):
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
    summary="Encrypt plaintext data",
    description="Encrypt plaintext using the specified algorithm. "
    "Returns base64-encoded ciphertext.",
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
        ciphertext_bytes = cipher.encrypt(body.plaintext)
        ciphertext_b64 = base64.b64encode(ciphertext_bytes).decode("ascii")
    else:
        encrypted_doc, _ = cipher.encrypt_document(body.plaintext)
        ciphertext_b64 = base64.b64encode(encrypted_doc).decode("ascii")

    return EncryptResponse(
        ciphertext=ciphertext_b64,
        algorithm=body.algorithm,
        request_id=request.state.request_id,
    )


@router.post(
    "/decrypt",
    response_model=DecryptResponse,
    summary="Decrypt ciphertext",
    description="Decrypt base64-encoded ciphertext using the specified algorithm.",
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
        plaintext_bytes = cipher.decrypt(ciphertext_bytes)
    else:
        plaintext_bytes = cipher.decrypt_document(ciphertext_bytes)

    return DecryptResponse(
        plaintext=plaintext_bytes.decode("utf-8"),
        algorithm=body.algorithm,
        request_id=request.state.request_id,
    )
