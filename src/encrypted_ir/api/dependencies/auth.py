"""Authentication and authorization dependencies for the API."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer


class Role(str, Enum):
    """User roles for RBAC."""

    ADMIN = "admin"
    WRITE = "write"
    READ = "read"


@dataclass
class TenantInfo:
    """Authenticated tenant information extracted from JWT or API key."""

    tenant_id: str
    roles: list[Role] = field(default_factory=lambda: [Role.READ])
    subject: str = ""


# Security schemes
bearer_scheme = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# Secret key for JWT verification - must be set via environment variable in production
JWT_SECRET = os.environ.get("ENCRYPTED_IR_JWT_SECRET", "dev-secret-change-in-production")
JWT_ALGORITHM = "HS256"

# In-memory API key store for development; replace with a database in production
_api_keys: dict[str, TenantInfo] = {}


def register_api_key(api_key: str, tenant_info: TenantInfo) -> None:
    """Register an API key (for testing and development)."""
    _api_keys[api_key] = tenant_info


def clear_api_keys() -> None:
    """Clear all registered API keys."""
    _api_keys.clear()


def _decode_jwt(token: str) -> dict:
    """Decode and validate a JWT token.

    Returns the token payload as a dict.

    Raises:
        HTTPException: If the token is invalid or expired.
    """
    try:
        import jwt

        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except ImportError:
        # Fallback: basic base64 decode for development without PyJWT
        import base64
        import json

        try:
            parts = token.split(".")
            if len(parts) != 3:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token format",
                )
            # Decode payload (part 1) - add padding
            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            return payload
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
            ) from e
    except jwt.ExpiredSignatureError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        ) from e
    except jwt.InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {e}",
        ) from e


def _extract_tenant_from_jwt(payload: dict) -> TenantInfo:
    """Extract tenant information from JWT payload."""
    tenant_id = payload.get("tenant_id")
    if not tenant_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing tenant_id claim",
        )

    roles_raw = payload.get("roles", ["read"])
    roles = []
    for r in roles_raw:
        try:
            roles.append(Role(r))
        except ValueError:
            continue
    if not roles:
        roles = [Role.READ]

    return TenantInfo(
        tenant_id=tenant_id,
        roles=roles,
        subject=payload.get("sub", ""),
    )


async def get_current_tenant(
    bearer: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
    api_key: Optional[str] = Security(api_key_header),
) -> TenantInfo:
    """Extract and validate the current tenant from auth credentials.

    Supports both Bearer JWT tokens and API key authentication.

    Raises:
        HTTPException: 401 if no valid credentials provided.
    """
    # Try Bearer token first
    if bearer is not None:
        payload = _decode_jwt(bearer.credentials)
        return _extract_tenant_from_jwt(payload)

    # Try API key
    if api_key is not None:
        tenant_info = _api_keys.get(api_key)
        if tenant_info is not None:
            return tenant_info
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_role(*required_roles: Role):
    """Dependency that enforces role-based access control.

    Usage:
        @router.post("/admin-only", dependencies=[Depends(require_role(Role.ADMIN))])
    """

    async def _check_role(
        tenant: TenantInfo = Depends(get_current_tenant),
    ) -> TenantInfo:
        if not any(role in tenant.roles for role in required_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required: {[r.value for r in required_roles]}",
            )
        return tenant

    return _check_role
