"""Admin endpoints: health check, readiness and metrics."""

from __future__ import annotations

import hmac
import logging
import time

from fastapi import APIRouter, Request, Response, status
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST
from sqlalchemy.engine import Engine

from encrypted_ir import __version__
from encrypted_ir.migrations import database_connects, migration_status
from encrypted_ir.settings import EncryptedIRSettings

from ..middleware import error_body
from ..models.responses import HealthResponse, ReadinessResponse

logger = logging.getLogger(__name__)

router = APIRouter(tags=["admin"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Returns service health status, version, and uptime.",
)
async def health_check(request: Request) -> HealthResponse:
    return HealthResponse(
        status="healthy",
        version=__version__,
        uptime_seconds=round(time.monotonic() - request.app.state.started_at, 2),
    )


def _database_ready(engine: Engine) -> bool:
    try:
        return database_connects(engine)
    except Exception:
        logger.warning("Readiness: database check failed", exc_info=True)
        return False


def _migrations_ready(engine: Engine, settings: EncryptedIRSettings) -> bool:
    if settings.auto_create_tables:
        return True
    try:
        info = migration_status(engine, settings.database_url)
    except Exception:
        logger.warning("Readiness: migration check failed", exc_info=True)
        return False
    if not info["at_head"]:
        logger.warning(
            "Readiness: database revision %s is not at head %s", info["current"], info["head"]
        )
    return bool(info["at_head"])


def _auth_ready(settings: EncryptedIRSettings) -> bool:
    oidc_configured = bool(
        settings.oidc_issuer and settings.oidc_audience and settings.oidc_jwks_url
    )
    ready = oidc_configured or (settings.dev_auth_enabled and not settings.is_production)
    if not ready:
        logger.warning("Readiness: no authentication method is configured")
    return ready


def _key_provider_ready(request: Request, settings: EncryptedIRSettings) -> bool:
    key_source = getattr(request.app.state, "master_key_source", "unknown")
    ready = key_source == "aws-kms" if settings.is_production else key_source != "unknown"
    if not ready:
        logger.warning("Readiness: master key source %r is not acceptable", key_source)
    return bool(ready)


@router.get(
    "/ready",
    response_model=ReadinessResponse,
    summary="Readiness check",
    description=(
        "Reports whether the database, migrations, authentication and key provider are ready, "
        "as booleans. Failure details go to the server log, not the response."
    ),
)
def readiness_check(request: Request, response: Response) -> ReadinessResponse:
    settings: EncryptedIRSettings = request.app.state.settings
    checks = {
        "database": _database_ready(request.app.state.database_engine),
        "migrations": _migrations_ready(request.app.state.database_engine, settings),
        "auth": _auth_ready(settings),
        "key_provider": _key_provider_ready(request, settings),
    }

    ready = all(checks.values())
    if not ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return ReadinessResponse(status="ready" if ready else "not_ready", checks=checks)


@router.get(
    "/metrics",
    response_class=Response,
    summary="Prometheus metrics",
    description=(
        "Prometheus text exposition: requests by route template, method and status, latency "
        "histograms, auth rejections and the key-cache size. Labels never contain document IDs. "
        "When ENCRYPTED_IR_METRICS_TOKEN is set, a matching bearer token is required."
    ),
)
async def get_metrics(request: Request) -> Response:
    token = request.app.state.settings.metrics_token
    if token:
        presented = request.headers.get("authorization", "").encode()
        if not hmac.compare_digest(presented, f"Bearer {token}".encode()):
            request.state.auth_failure = "invalid_metrics_token"
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content=error_body("unauthorized", "Not authenticated", request.state.request_id),
                headers={"WWW-Authenticate": "Bearer"},
            )
    return Response(content=request.app.state.metrics.collect(), media_type=CONTENT_TYPE_LATEST)
