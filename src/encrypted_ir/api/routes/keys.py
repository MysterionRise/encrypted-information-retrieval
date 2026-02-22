"""Key management endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from encrypted_ir.key_manager import KeyManager

from ..dependencies.auth import Role, TenantInfo, require_role
from ..dependencies.rate_limiter import RateLimiter, get_rate_limiter
from ..models.requests import KeyRotateRequest
from ..models.responses import KeyInfoResponse, KeyListResponse, KeyRotateResponse

router = APIRouter(prefix="/v1/keys", tags=["keys"])

# Per-tenant key managers (in production, backed by KMS + persistent storage)
_tenant_key_managers: dict[str, KeyManager] = {}


def _get_key_manager(tenant_id: str) -> KeyManager:
    if tenant_id not in _tenant_key_managers:
        _tenant_key_managers[tenant_id] = KeyManager()
    return _tenant_key_managers[tenant_id]


def reset_key_managers() -> None:
    """Reset all per-tenant key managers (for testing)."""
    _tenant_key_managers.clear()


@router.get(
    "",
    response_model=KeyListResponse,
    summary="List active keys",
    description="List all active encryption keys for the authenticated tenant.",
)
async def list_keys(
    request: Request,
    tenant: TenantInfo = Depends(require_role(Role.READ, Role.WRITE, Role.ADMIN)),
    rate_limiter: RateLimiter = Depends(get_rate_limiter),
) -> KeyListResponse:
    rate_limiter.check_limit(tenant.tenant_id, "read")

    km = _get_key_manager(tenant.tenant_id)
    key_ids = km.list_keys(active_only=True)

    keys = []
    for key_id in key_ids:
        metadata = km.get_metadata(key_id)
        keys.append(
            KeyInfoResponse(
                key_id=key_id,
                key_type=metadata.key_type,
                created_at=metadata.created_at.isoformat(),
                active=metadata.active,
                needs_rotation=metadata.needs_rotation(),
                access_count=metadata.access_count,
            )
        )

    return KeyListResponse(
        keys=keys,
        count=len(keys),
        request_id=request.state.request_id,
    )


@router.post(
    "/rotate",
    response_model=KeyRotateResponse,
    summary="Rotate an encryption key",
    description="Create a new version of a key and deactivate the old one. " "Requires admin role.",
)
async def rotate_key(
    body: KeyRotateRequest,
    request: Request,
    tenant: TenantInfo = Depends(require_role(Role.ADMIN)),
    rate_limiter: RateLimiter = Depends(get_rate_limiter),
) -> KeyRotateResponse:
    rate_limiter.check_limit(tenant.tenant_id, "key_rotate")

    km = _get_key_manager(tenant.tenant_id)
    new_key_id = km.rotate_key(body.key_id)

    return KeyRotateResponse(
        old_key_id=body.key_id,
        new_key_id=new_key_id,
        request_id=request.state.request_id,
    )
