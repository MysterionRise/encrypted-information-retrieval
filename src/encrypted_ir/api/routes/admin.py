"""Admin endpoints: health check, readiness and metrics."""

from __future__ import annotations

import logging
import time
from typing import Literal, TypedDict

from fastapi import APIRouter, Request, Response, status
from sqlalchemy.engine import Engine

from encrypted_ir import __version__
from encrypted_ir.migrations import database_connects, migration_status
from encrypted_ir.settings import EncryptedIRSettings

from ..models.responses import HealthResponse, MetricsResponse, ReadinessResponse

logger = logging.getLogger(__name__)

router = APIRouter(tags=["admin"])

_start_time: float = time.time()


class MetricsState(TypedDict):
    request_count: int
    error_count: int
    active_tenants: set[str]
    requests_by_endpoint: dict[str, int]
    total_latency_ms: float
    unauthorized_count: int
    forbidden_count: int
    rate_limited_count: int
    security_audit_dropped_count: int


# Simple in-memory metrics counters
_metrics: MetricsState = {
    "request_count": 0,
    "error_count": 0,
    "active_tenants": set[str](),
    "requests_by_endpoint": {},
    "total_latency_ms": 0.0,
    "unauthorized_count": 0,
    "forbidden_count": 0,
    "rate_limited_count": 0,
    "security_audit_dropped_count": 0,
}

RejectionCounter = Literal["unauthorized_count", "forbidden_count", "rate_limited_count"]

_REJECTION_COUNTERS: dict[int, RejectionCounter] = {
    401: "unauthorized_count",
    403: "forbidden_count",
    429: "rate_limited_count",
}


def record_request(endpoint: str, tenant_id: str | None, latency_ms: float) -> None:
    """Record a request for metrics."""
    _metrics["request_count"] += 1
    _metrics["requests_by_endpoint"][endpoint] = (
        _metrics["requests_by_endpoint"].get(endpoint, 0) + 1
    )
    _metrics["total_latency_ms"] += latency_ms
    if tenant_id:
        _metrics["active_tenants"].add(tenant_id)


def record_error() -> None:
    """Record an error for metrics."""
    _metrics["error_count"] += 1


def record_rejection(status_code: int) -> None:
    """Count a 401, 403 or 429 response."""
    counter = _REJECTION_COUNTERS.get(status_code)
    if counter is not None:
        _metrics[counter] += 1


def record_security_audit_dropped() -> None:
    """Count a rejection that was not audited because the audit rate bound was reached."""
    _metrics["security_audit_dropped_count"] += 1


def reset_metrics() -> None:
    """Reset all metrics (for testing)."""
    global _start_time
    _start_time = time.time()
    _metrics["request_count"] = 0
    _metrics["error_count"] = 0
    _metrics["active_tenants"] = set[str]()
    _metrics["requests_by_endpoint"] = {}
    _metrics["total_latency_ms"] = 0.0
    _metrics["unauthorized_count"] = 0
    _metrics["forbidden_count"] = 0
    _metrics["rate_limited_count"] = 0
    _metrics["security_audit_dropped_count"] = 0


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Returns service health status, version, and uptime.",
)
async def health_check() -> HealthResponse:
    return HealthResponse(
        status="healthy",
        version=__version__,
        uptime_seconds=round(time.time() - _start_time, 2),
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
    response_model=MetricsResponse,
    summary="Service metrics",
    description="Returns Prometheus-style metrics for monitoring.",
)
async def get_metrics() -> MetricsResponse:
    request_count = _metrics["request_count"]
    avg_latency = _metrics["total_latency_ms"] / request_count if request_count > 0 else 0.0

    return MetricsResponse(
        request_count=request_count,
        error_count=_metrics["error_count"],
        active_tenants=len(_metrics["active_tenants"]),
        requests_by_endpoint=dict(_metrics["requests_by_endpoint"]),
        avg_latency_ms=round(avg_latency, 2),
        unauthorized_count=_metrics["unauthorized_count"],
        forbidden_count=_metrics["forbidden_count"],
        rate_limited_count=_metrics["rate_limited_count"],
        security_audit_dropped_count=_metrics["security_audit_dropped_count"],
    )
