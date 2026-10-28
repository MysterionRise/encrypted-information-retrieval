"""FastAPI application factory for Encrypted Information Retrieval API."""

from __future__ import annotations

import time

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from encrypted_ir import __version__
from encrypted_ir.database import create_database_engine, create_database_schema
from encrypted_ir.document_service import DocumentService
from encrypted_ir.errors import DocumentAlreadyExistsError
from encrypted_ir.logging import LoggingConfig
from encrypted_ir.master_key import resolve_master_key
from encrypted_ir.metrics import EncryptionMetrics
from encrypted_ir.settings import EncryptedIRSettings

from .dependencies.auth import AuthConfig, OIDCVerifier
from .dependencies.rate_limiter import RateLimiter
from .middleware import (
    HTTP_413_CONTENT_TOO_LARGE,
    BodySizeLimitMiddleware,
    RequestBodyTooLargeError,
    SecurityAuditLimiter,
    error_body,
)
from .request_context import SYSTEM_TENANT_ID, RequestContextMiddleware
from .routes import admin, documents

CORS_ALLOWED_METHODS = ["GET", "POST", "DELETE"]
CORS_ALLOWED_HEADERS = ["Authorization", "Content-Type", "X-API-Key", "X-Request-ID"]
CORS_EXPOSED_HEADERS = ["X-Request-ID", "X-Response-Time-Ms", "Retry-After"]


def create_app(settings: EncryptedIRSettings | None = None) -> FastAPI:  # noqa: C901
    """Create and configure the FastAPI application."""
    settings = settings or EncryptedIRSettings.from_env()
    settings.validate()
    LoggingConfig(level=settings.log_level, extra_loggers=("uvicorn.error",)).setup()
    app = FastAPI(
        title="Encrypted Information Retrieval API",
        description=(
            "Prototype API for tenant-scoped encrypted document storage, keyword-token "
            "search and RAG-ready retrieval. Documents are AES-GCM encrypted under "
            "per-tenant keys; search matches HMAC keyword tokens. See "
            "docs/LEAKAGE_AND_ENDPOINTS.md for what each route reveals."
        ),
        version=__version__,
        docs_url="/docs" if settings.enable_docs else None,
        redoc_url="/redoc" if settings.enable_docs else None,
        openapi_url="/openapi.json" if settings.enable_docs else None,
    )
    app.state.settings = settings
    app.state.started_at = time.monotonic()
    app.state.auth_config = AuthConfig.from_settings(settings)
    app.state.oidc_verifier = OIDCVerifier(app.state.auth_config)
    app.state.database_engine = create_database_engine(settings.database_url)
    if settings.auto_create_tables:
        create_database_schema(app.state.database_engine)
    master_key, master_key_source = resolve_master_key(settings)
    app.state.master_key_source = master_key_source
    app.state.document_service = DocumentService(
        app.state.database_engine,
        master_key,
    )
    if master_key_source == "aws-kms":
        app.state.document_service.record_audit_event(
            tenant_id=SYSTEM_TENANT_ID,
            event_type="key.unwrap",
            actor="api-startup",
            success=True,
            resource=settings.aws_kms_key_id or "",
            details={"key_source": master_key_source},
            request_id="startup",
        )
    app.state.security_audit_limiter = SecurityAuditLimiter()
    app.state.metrics = EncryptionMetrics()
    app.state.rate_limiter = RateLimiter.from_limits(
        settings.effective_rate_limits, max_keys=settings.rate_limit_max_keys
    )
    app.state.metrics.track_key_cache(app.state.document_service.cached_tenant_count)

    # Middleware added later wraps middleware added earlier, so requests pass through the
    # request context first, then CORS, then the body limit.
    app.add_middleware(BodySizeLimitMiddleware, max_body_bytes=settings.max_body_bytes)

    # Credentials are only allowed with an explicit origin list, never with "*".
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials="*" not in settings.cors_origins,
        allow_methods=CORS_ALLOWED_METHODS,
        allow_headers=CORS_ALLOWED_HEADERS,
        expose_headers=CORS_EXPOSED_HEADERS,
    )

    # Request ID, client rate limit, access log, metrics, rejection audit, JSON 500 body.
    app.add_middleware(RequestContextMiddleware)

    # Behind a reverse proxy, take the client address from X-Forwarded-For, but only when the
    # direct peer is a configured trusted proxy. Run uvicorn with --no-proxy-headers so the
    # headers are not processed twice.
    if settings.trusted_proxies:
        app.add_middleware(ProxyHeadersMiddleware, trusted_hosts=list(settings.trusted_proxies))

    # Custom exception handlers
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        details = []
        for error in exc.errors():
            loc = ".".join(str(part) for part in error["loc"])
            details.append({"field": loc, "message": error["msg"]})
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": "validation_error",
                "message": "Request validation failed",
                "request_id": getattr(request.state, "request_id", "unknown"),
                "details": details,
            },
        )

    @app.exception_handler(RequestBodyTooLargeError)
    async def body_too_large_handler(request: Request, exc: RequestBodyTooLargeError):
        return JSONResponse(
            status_code=HTTP_413_CONTENT_TOO_LARGE,
            content=error_body(
                "request_too_large",
                "Request body too large",
                getattr(request.state, "request_id", "unknown"),
            ),
        )

    @app.exception_handler(DocumentAlreadyExistsError)
    async def conflict_handler(request: Request, exc: DocumentAlreadyExistsError):
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={
                "error": "conflict",
                "message": "A document with this ID already exists",
                "request_id": getattr(request.state, "request_id", "unknown"),
                "details": [],
            },
        )

    # Exception text can name tenants, keys or internals, so it is never sent to the client.
    @app.exception_handler(ValueError)
    async def value_error_handler(request: Request, exc: ValueError):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=error_body(
                "bad_request",
                "Invalid request",
                getattr(request.state, "request_id", "unknown"),
            ),
        )

    @app.exception_handler(KeyError)
    async def key_error_handler(request: Request, exc: KeyError):
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=error_body(
                "not_found",
                "Resource not found",
                getattr(request.state, "request_id", "unknown"),
            ),
        )

    # Unhandled exceptions are turned into the JSON 500 body by RequestContextMiddleware, so
    # they keep the request ID and are counted.

    # Register routers
    app.include_router(documents.router)
    app.include_router(admin.router)

    # Route templates for requests that never reach a route (404s, early rejections).
    app.state.route_index = [
        *documents.router.routes,
        *admin.router.routes,
        *(route for route in app.router.routes if isinstance(getattr(route, "path", None), str)),
    ]

    return app
