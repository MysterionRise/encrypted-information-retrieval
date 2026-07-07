"""FastAPI application factory for Encrypted Information Retrieval API."""

from __future__ import annotations

import time
import uuid

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from encrypted_ir.database import create_database_engine, create_database_schema
from encrypted_ir.document_service import DocumentService
from encrypted_ir.master_key import resolve_master_key
from encrypted_ir.settings import EncryptedIRSettings

from .dependencies.auth import AuthConfig, OIDCVerifier
from .routes import admin, data, documents, keys, search


def create_app(settings: EncryptedIRSettings | None = None) -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = settings or EncryptedIRSettings.from_env()
    settings.validate()
    app = FastAPI(
        title="Encrypted Information Retrieval API",
        description=(
            "Production-oriented prototype API for encrypted search and RAG-ready "
            "retrieval workflows. Supports blind-index equality search, prototype "
            "ORE range queries, keyword-token document search, and AES-SIV/AES-GCM "
            "encryption with demo auth and tenant isolation."
        ),
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
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
            tenant_id="_system",
            event_type="key.unwrap",
            actor="api-startup",
            success=True,
            resource=settings.aws_kms_key_id or "",
            details={"key_source": master_key_source},
            request_id="startup",
        )

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Request ID and timing middleware
    @app.middleware("http")
    async def add_request_context(request: Request, call_next):
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
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

        return response

    # Request size limit middleware
    @app.middleware("http")
    async def limit_request_size(request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > 10 * 1024 * 1024:  # 10 MB
            return JSONResponse(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                content={
                    "error": "request_too_large",
                    "message": "Request body exceeds 10 MB limit",
                    "request_id": request.headers.get("X-Request-ID", "unknown"),
                    "details": [],
                },
            )
        return await call_next(request)

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

    @app.exception_handler(ValueError)
    async def value_error_handler(request: Request, exc: ValueError):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "error": "bad_request",
                "message": str(exc),
                "request_id": getattr(request.state, "request_id", "unknown"),
                "details": [],
            },
        )

    @app.exception_handler(KeyError)
    async def key_error_handler(request: Request, exc: KeyError):
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={
                "error": "not_found",
                "message": str(exc),
                "request_id": getattr(request.state, "request_id", "unknown"),
                "details": [],
            },
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
    app.include_router(data.router)
    app.include_router(search.router)
    app.include_router(documents.router)
    app.include_router(keys.router)
    app.include_router(admin.router)

    return app
