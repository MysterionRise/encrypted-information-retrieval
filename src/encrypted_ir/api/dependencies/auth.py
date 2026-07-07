"""Authentication and authorization dependencies for the API."""

from __future__ import annotations

import os
import warnings
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from encrypted_ir.settings import EncryptedIRSettings


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


@dataclass(frozen=True)
class AuthConfig:
    """Runtime authentication configuration."""

    environment: str = "dev"
    dev_auth_enabled: bool = True
    jwt_secret: str = "dev-secret-change-in-production"
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_url: str | None = None
    tenant_claim: str = "tenant_id"
    roles_claim: str = "roles"
    dev_api_key: str = "local-demo-key"
    dev_tenant_id: str = "local-demo"

    @classmethod
    def from_settings(cls, settings: EncryptedIRSettings) -> AuthConfig:
        return cls(
            environment=settings.environment,
            dev_auth_enabled=settings.dev_auth_enabled,
            jwt_secret=os.environ.get("ENCRYPTED_IR_JWT_SECRET", JWT_SECRET),
            oidc_issuer=settings.oidc_issuer,
            oidc_audience=settings.oidc_audience,
            oidc_jwks_url=settings.oidc_jwks_url,
            tenant_claim=settings.tenant_claim,
            roles_claim=settings.roles_claim,
            dev_api_key=os.environ.get("ENCRYPTED_IR_DEV_API_KEY", DEV_API_KEY),
            dev_tenant_id=os.environ.get("ENCRYPTED_IR_DEV_TENANT_ID", DEV_TENANT_ID),
        )

    @property
    def oidc_enabled(self) -> bool:
        return bool(self.oidc_issuer and self.oidc_audience and self.oidc_jwks_url)


class OIDCVerifier:
    """Verify OIDC JWTs against a configured JWKS endpoint."""

    def __init__(self, config: AuthConfig, jwks_client: Any | None = None):
        self._config = config
        self._jwks_client = jwks_client

    def _client(self):
        if self._jwks_client is None:
            import jwt

            if not self._config.oidc_jwks_url:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="OIDC JWKS URL is not configured",
                )
            self._jwks_client = jwt.PyJWKClient(self._config.oidc_jwks_url)
        return self._jwks_client

    def decode(self, token: str) -> dict:
        """Decode and validate an OIDC token."""
        try:
            import jwt

            signing_key = self._client().get_signing_key_from_jwt(token)
            return jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self._config.oidc_audience,
                issuer=self._config.oidc_issuer,
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid OIDC token: {e}",
            ) from e


# Security schemes
bearer_scheme = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# Secret key for JWT verification - must be set via environment variable in production
JWT_SECRET = os.environ.get("ENCRYPTED_IR_JWT_SECRET", "dev-secret-change-in-production")
JWT_ALGORITHM = "HS256"
DEV_AUTH_ENABLED = os.environ.get("ENCRYPTED_IR_DEV_AUTH_ENABLED", "true").lower() in {
    "1",
    "true",
    "yes",
    "on",
}
DEV_API_KEY = os.environ.get("ENCRYPTED_IR_DEV_API_KEY", "local-demo-key")
DEV_TENANT_ID = os.environ.get("ENCRYPTED_IR_DEV_TENANT_ID", "local-demo")

if JWT_SECRET == "dev-secret-change-in-production":
    if not DEV_AUTH_ENABLED:
        raise RuntimeError(
            "ENCRYPTED_IR_JWT_SECRET must be set when ENCRYPTED_IR_DEV_AUTH_ENABLED=false"
        )
    warnings.warn(
        "Using development JWT secret. Set ENCRYPTED_IR_JWT_SECRET and disable "
        "ENCRYPTED_IR_DEV_AUTH_ENABLED outside local demos.",
        RuntimeWarning,
        stacklevel=2,
    )

# In-memory API key store for development; replace with a database in production
_api_keys: dict[str, TenantInfo] = {}


def register_api_key(api_key: str, tenant_info: TenantInfo) -> None:
    """Register an API key (for testing and development)."""
    _api_keys[api_key] = tenant_info


def clear_api_keys() -> None:
    """Clear all registered API keys."""
    _api_keys.clear()


def _decode_dev_jwt(token: str, config: AuthConfig) -> dict:
    """Decode and validate a JWT token.

    Returns the token payload as a dict.

    Raises:
        HTTPException: If the token is invalid or expired.
    """

    def _decode_unsigned_dev_payload() -> dict:
        import base64
        import json

        parts = token.split(".")
        if len(parts) != 3:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token format",
            )
        payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(payload_b64))

    try:
        import jwt

        payload = jwt.decode(token, config.jwt_secret, algorithms=[JWT_ALGORITHM])
        return payload
    except ImportError:
        if not config.dev_auth_enabled:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="PyJWT is required when development auth is disabled",
            )
        try:
            return _decode_unsigned_dev_payload()
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
        if config.dev_auth_enabled:
            try:
                return _decode_unsigned_dev_payload()
            except Exception:
                pass
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {e}",
        ) from e


def _extract_tenant_from_jwt(payload: dict, config: AuthConfig | None = None) -> TenantInfo:
    """Extract tenant information from JWT payload."""
    config = config or AuthConfig()
    tenant_id = payload.get(config.tenant_claim)
    if not tenant_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token missing {config.tenant_claim} claim",
        )

    roles_raw = payload.get(config.roles_claim)
    if roles_raw is None:
        if not config.dev_auth_enabled:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Token missing {config.roles_claim} claim",
            )
        roles_raw = ["read"]
    if isinstance(roles_raw, str):
        roles_raw = roles_raw.split()
    elif not isinstance(roles_raw, (list, tuple, set)):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token {config.roles_claim} claim must be a string or list",
        )
    if not roles_raw:
        if not config.dev_auth_enabled:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Token {config.roles_claim} claim is empty",
            )
        roles_raw = ["read"]

    roles = []
    unknown_roles = []
    for r in roles_raw:
        try:
            roles.append(Role(str(r)))
        except ValueError:
            unknown_roles.append(str(r))
    if unknown_roles and not config.dev_auth_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Token contains unrecognized roles: {unknown_roles}",
        )
    if not roles:
        if not config.dev_auth_enabled:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Token contains no valid {config.roles_claim} roles",
            )
        roles = [Role.READ]

    return TenantInfo(
        tenant_id=tenant_id,
        roles=roles,
        subject=payload.get("sub", ""),
    )


async def get_current_tenant(
    request: Request,
    bearer: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
    api_key: Optional[str] = Security(api_key_header),
) -> TenantInfo:
    """Extract and validate the current tenant from auth credentials.

    Supports both Bearer JWT tokens and API key authentication.

    Raises:
        HTTPException: 401 if no valid credentials provided.
    """
    config = getattr(request.app.state, "auth_config", AuthConfig())

    # Try Bearer token first
    if bearer is not None:
        if config.oidc_enabled:
            verifier = getattr(request.app.state, "oidc_verifier", None)
            if verifier is None:
                verifier = OIDCVerifier(config)
                request.app.state.oidc_verifier = verifier
            payload = verifier.decode(bearer.credentials)
        elif config.dev_auth_enabled:
            payload = _decode_dev_jwt(bearer.credentials, config)
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="OIDC authentication is not configured",
            )
        tenant = _extract_tenant_from_jwt(payload, config)
        request.state.tenant_id = tenant.tenant_id
        request.state.actor = tenant.subject
        return tenant

    # Try API key
    if api_key is not None:
        tenant_info = _api_keys.get(api_key)
        if tenant_info is not None:
            if config.environment == "prod":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="API key authentication is disabled in production",
                )
            request.state.tenant_id = tenant_info.tenant_id
            request.state.actor = tenant_info.subject
            return tenant_info
        if config.dev_auth_enabled and api_key == config.dev_api_key:
            tenant = TenantInfo(
                tenant_id=config.dev_tenant_id,
                roles=[Role.ADMIN, Role.WRITE, Role.READ],
                subject="local-dev-api-key",
            )
            request.state.tenant_id = tenant.tenant_id
            request.state.actor = tenant.subject
            return tenant
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
