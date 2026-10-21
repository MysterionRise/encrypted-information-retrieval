"""Authentication and authorization dependencies for the API.

All configuration comes from :class:`AuthConfig`, which the app builds from validated settings at
startup; nothing is read from the environment at import time. If the app has no auth config,
every request is rejected.

Every authentication failure returns the same generic 401 body. The specific reason (for
example ``token_expired`` or ``invalid_tenant_claim``) is stored on
``request.state.auth_failure`` for metrics and the audit log and is never sent to the client.

The dependencies are plain ``def`` functions, so FastAPI runs them in its thread pool: a slow
JWKS fetch blocks one worker thread, not the event loop.
"""

from __future__ import annotations

import hmac
import re
import threading
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, cast

import jwt
from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from encrypted_ir.settings import TENANT_ID_PATTERN, EncryptedIRSettings

DEV_JWT_ALGORITHM = "HS256"
MAX_SUBJECT_LENGTH = 256


class Role(StrEnum):
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


class AuthenticationError(HTTPException):
    """401 with a generic body. ``reason`` is for logs and audit only."""

    def __init__(self, reason: str):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
        self.reason = reason


class AuthorizationError(HTTPException):
    """403 with a generic body. ``reason`` is for logs and audit only."""

    def __init__(self, reason: str):
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        self.reason = reason


@dataclass(frozen=True)
class AuthConfig:
    """Runtime authentication configuration."""

    environment: str = "dev"
    dev_auth_enabled: bool = False
    jwt_secret: str | None = field(default=None, repr=False)
    dev_api_key: str | None = field(default=None, repr=False)
    dev_tenant_id: str = "local-demo"
    leeway_seconds: int = 30
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_url: str | None = None
    oidc_algorithms: tuple[str, ...] = ("RS256",)
    jwks_timeout_seconds: float = 5.0
    tenant_claim: str = "tenant_id"
    roles_claim: str = "roles"

    @classmethod
    def from_settings(cls, settings: EncryptedIRSettings) -> AuthConfig:
        return cls(
            environment=settings.environment,
            dev_auth_enabled=settings.dev_auth_enabled,
            jwt_secret=settings.jwt_secret,
            dev_api_key=settings.dev_api_key,
            dev_tenant_id=settings.dev_tenant_id,
            leeway_seconds=settings.jwt_leeway_seconds,
            oidc_issuer=settings.oidc_issuer,
            oidc_audience=settings.oidc_audience,
            oidc_jwks_url=settings.oidc_jwks_url,
            oidc_algorithms=settings.oidc_algorithms,
            jwks_timeout_seconds=settings.jwks_timeout_seconds,
            tenant_claim=settings.tenant_claim,
            roles_claim=settings.roles_claim,
        )

    @property
    def oidc_enabled(self) -> bool:
        return bool(self.oidc_issuer and self.oidc_audience and self.oidc_jwks_url)


class OIDCVerifier:
    """Verify OIDC JWTs against a configured JWKS endpoint."""

    def __init__(self, config: AuthConfig, jwks_client: Any | None = None):
        self._config = config
        self._jwks_client = jwks_client
        self._lock = threading.Lock()

    def _client(self) -> Any:
        with self._lock:
            if self._jwks_client is None:
                if not self._config.oidc_jwks_url:
                    raise AuthenticationError("oidc_not_configured")
                self._jwks_client = jwt.PyJWKClient(
                    self._config.oidc_jwks_url,
                    timeout=self._config.jwks_timeout_seconds,
                )
            return self._jwks_client

    def decode(self, token: str) -> dict[str, Any]:
        """Verify ``token`` and return its claims.

        Requires ``exp``, ``iat``, ``aud`` and ``iss`` and accepts only the configured asymmetric
        algorithms.
        """
        try:
            signing_key = self._client().get_signing_key_from_jwt(token)
            return cast(
                dict[str, Any],
                jwt.decode(
                    token,
                    signing_key.key,
                    algorithms=list(self._config.oidc_algorithms),
                    audience=self._config.oidc_audience,
                    issuer=self._config.oidc_issuer,
                    leeway=self._config.leeway_seconds,
                    options={"require": ["exp", "iat", "aud", "iss"]},
                ),
            )
        except jwt.ExpiredSignatureError as e:
            raise AuthenticationError("token_expired") from e
        except jwt.PyJWKClientConnectionError as e:
            raise AuthenticationError("jwks_unavailable") from e
        except jwt.PyJWKClientError as e:
            raise AuthenticationError("unknown_signing_key") from e
        except jwt.PyJWTError as e:
            raise AuthenticationError("invalid_token") from e


# Security schemes
bearer_scheme = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def _decode_dev_jwt(token: str, config: AuthConfig) -> dict[str, Any]:
    """Verify a dev HS256 token signed with the configured secret."""
    if not config.jwt_secret:
        raise AuthenticationError("dev_auth_not_configured")
    try:
        return cast(
            dict[str, Any],
            jwt.decode(
                token,
                config.jwt_secret,
                algorithms=[DEV_JWT_ALGORITHM],
                leeway=config.leeway_seconds,
                options={"require": ["exp", "iat"]},
            ),
        )
    except jwt.ExpiredSignatureError as e:
        raise AuthenticationError("token_expired") from e
    except jwt.PyJWTError as e:
        raise AuthenticationError("invalid_token") from e


def _parse_roles(roles_raw: Any) -> list[Role]:
    if isinstance(roles_raw, str):
        roles_raw = roles_raw.split()
    elif not isinstance(roles_raw, list) or not all(isinstance(r, str) for r in roles_raw):
        raise AuthenticationError("invalid_roles_claim")
    if not roles_raw:
        raise AuthenticationError("invalid_roles_claim")

    roles: list[Role] = []
    for value in roles_raw:
        try:
            role = Role(value)
        except ValueError as e:
            raise AuthorizationError("unknown_role") from e
        if role not in roles:
            roles.append(role)
    return roles


def _extract_tenant_from_jwt(payload: dict[str, Any], config: AuthConfig) -> TenantInfo:
    """Extract tenant information from verified JWT claims.

    The tenant claim must be a string matching :data:`TENANT_ID_PATTERN`, and the roles claim
    must be a non-empty list (or space-separated string) of known roles. The same rules apply
    to dev and OIDC tokens.
    """
    tenant_id = payload.get(config.tenant_claim)
    if not isinstance(tenant_id, str) or not re.fullmatch(TENANT_ID_PATTERN, tenant_id):
        raise AuthenticationError("invalid_tenant_claim")

    subject = payload.get("sub")
    return TenantInfo(
        tenant_id=tenant_id,
        roles=_parse_roles(payload.get(config.roles_claim)),
        subject=subject[:MAX_SUBJECT_LENGTH] if isinstance(subject, str) else "",
    )


def _verifier(request: Request) -> OIDCVerifier:
    verifier = getattr(request.app.state, "oidc_verifier", None)
    if not isinstance(verifier, OIDCVerifier):
        raise AuthenticationError("oidc_not_configured")
    return verifier


def _authenticate(
    request: Request,
    bearer: HTTPAuthorizationCredentials | None,
    api_key: str | None,
) -> TenantInfo:
    config = getattr(request.app.state, "auth_config", None)
    if not isinstance(config, AuthConfig):
        raise AuthenticationError("auth_not_configured")

    if bearer is not None:
        if config.oidc_enabled:
            payload = _verifier(request).decode(bearer.credentials)
        elif config.dev_auth_enabled:
            payload = _decode_dev_jwt(bearer.credentials, config)
        else:
            raise AuthenticationError("bearer_auth_not_configured")
        return _extract_tenant_from_jwt(payload, config)

    if api_key is not None:
        if (
            config.dev_auth_enabled
            and config.dev_api_key
            and hmac.compare_digest(api_key.encode(), config.dev_api_key.encode())
        ):
            return TenantInfo(
                tenant_id=config.dev_tenant_id,
                roles=[Role.ADMIN, Role.WRITE, Role.READ],
                subject="local-dev-api-key",
            )
        raise AuthenticationError("invalid_api_key")

    raise AuthenticationError("missing_credentials")


def get_current_tenant(
    request: Request,
    bearer: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
    api_key: str | None = Security(api_key_header),
) -> TenantInfo:
    """Authenticate the request from a Bearer JWT or the dev API key.

    Raises:
        AuthenticationError: 401 with a generic body if the credentials are missing or invalid.
        AuthorizationError: 403 if a token names a role this service does not know.
    """
    try:
        tenant = _authenticate(request, bearer, api_key)
    except (AuthenticationError, AuthorizationError) as exc:
        request.state.auth_failure = exc.reason
        raise
    request.state.tenant_id = tenant.tenant_id
    request.state.actor = tenant.subject
    return tenant


def require_role(*required_roles: Role):
    """Dependency that enforces role-based access control.

    Usage:
        @router.post("/admin-only", dependencies=[Depends(require_role(Role.ADMIN))])
    """

    def _check_role(
        request: Request,
        tenant: TenantInfo = Depends(get_current_tenant),
    ) -> TenantInfo:
        if not any(role in tenant.roles for role in required_roles):
            request.state.auth_failure = "insufficient_role"
            raise AuthorizationError("insufficient_role")
        return tenant

    return _check_role
