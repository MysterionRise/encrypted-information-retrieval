"""FastAPI application factory for Encrypted Information Retrieval API."""

from __future__ import annotations

import logging
import time

from fastapi import FastAPI, Request, status
from fastapi.concurrency import run_in_threadpool
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from encrypted_ir import __version__
from encrypted_ir.database import create_database_engine, create_database_schema
from encrypted_ir.document_service import DocumentService
from encrypted_ir.errors import DocumentAlreadyExistsError
from encrypted_ir.master_key import resolve_master_key
from encrypted_ir.settings import EncryptedIRSettings

from .dependencies.auth import AuthConfig, OIDCVerifier
from .middleware import (
    HTTP_413_CONTENT_TOO_LARGE,
    BodySizeLimitMiddleware,
    RequestBodyTooLargeError,
    SecurityAuditLimiter,
    error_body,
    sanitize_request_id,
)
from .routes import admin, documents

logger = logging.getLogger(__name__)

SYSTEM_TENANT_ID = "_system"

# Rejections that are counted in /metrics and written (rate-bounded) to the audit log.
SECURITY_EVENTS = {
    status.HTTP_401_UNAUTHORIZED: ("auth.failure", "unauthenticated"),
    status.HTTP_403_FORBIDDEN: ("authz.failure", "forbidden"),
    status.HTTP_429_TOO_MANY_REQUESTS: ("rate_limit.exceeded", "rate_limited"),
}

CORS_ALLOWED_METHODS = ["GET", "POST", "DELETE"]
CORS_ALLOWED_HEADERS = ["Authorization", "Content-Type", "X-API-Key", "X-Request-ID"]
CORS_EXPOSED_HEADERS = ["X-Request-ID", "X-Response-Time-Ms", "Retry-After"]


def create_app(settings: EncryptedIRSettings | None = None) -> FastAPI:  # noqa: C901
    """Create and configure the FastAPI application."""
    settings = settings or EncryptedIRSettings.from_env()
    settings.validate()
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

    async def audit_rejection(request: Request, status_code: int) -> None:
        """Count a 401/403/429 and write a rate-bounded audit row for it."""
        admin.record_rejection(status_code)
        if not app.state.security_audit_limiter.allow():
            admin.record_security_audit_dropped()
            return

        event_type, default_reason = SECURITY_EVENTS[status_code]
        route = request.scope.get("route")
        try:
            await run_in_threadpool(
                app.state.document_service.record_audit_event,
                tenant_id=getattr(request.state, "tenant_id", None) or SYSTEM_TENANT_ID,
                event_type=event_type,
                actor=getattr(request.state, "actor", None) or "anonymous",
                success=False,
                resource=getattr(route, "path", ""),
                details={
                    "status": status_code,
                    "method": request.method,
                    "reason": getattr(request.state, "auth_failure", default_reason),
                },
                request_id=request.state.request_id,
            )
        except Exception:
            logger.warning("Failed to audit a rejected request", exc_info=True)

    # Request ID, timing, metrics and security-event middleware
    @app.middleware("http")
    async def add_request_context(request: Request, call_next):
        request_id = sanitize_request_id(request.headers.get("X-Request-ID"))
        request.state.request_id = request_id
        start_time = time.monotonic()

        response = await call_next(request)

        latency_ms = (time.monotonic() - start_time) * 1000
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time-Ms"] = f"{latency_ms:.2f}"

        # Record metrics
        tenant_id = getattr(request.state, "tenant_id", None)
        admin.record_request(request.url.path, tenant_id, latency_ms)

        if response.status_code >= 400:
            admin.record_error()
        if response.status_code in SECURITY_EVENTS:
            await audit_rejection(request, response.status_code)

        return response

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

    @app.exception_handler(Exception)
    async def general_exception_handler(request: Request, exc: Exception):
        request_id = getattr(request.state, "request_id", "unknown")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "internal_error",
                "message": f"Internal server error (request_id: {request_id})",
                "request_id": request_id,
                "details": [],
            },
        )

    # Register routers
    app.include_router(documents.router)
    app.include_router(admin.router)

    return app
