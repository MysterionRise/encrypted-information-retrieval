"""Admin endpoints: health check and metrics."""

from __future__ import annotations

import time
from typing import TypedDict

from fastapi import APIRouter, Request, Response, status

from encrypted_ir.migrations import database_connects, migration_status

from ..models.responses import HealthResponse, MetricsResponse, ReadinessResponse

router = APIRouter(tags=["admin"])

_start_time: float = time.time()


class MetricsState(TypedDict):
    request_count: int
    error_count: int
    active_tenants: set[str]
    requests_by_endpoint: dict[str, int]
    total_latency_ms: float


# Simple in-memory metrics counters
_metrics: MetricsState = {
    "request_count": 0,
    "error_count": 0,
    "active_tenants": set[str](),
    "requests_by_endpoint": {},
    "total_latency_ms": 0.0,
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


def reset_metrics() -> None:
    """Reset all metrics (for testing)."""
    global _start_time
    _start_time = time.time()
    _metrics["request_count"] = 0
    _metrics["error_count"] = 0
    _metrics["active_tenants"] = set[str]()
    _metrics["requests_by_endpoint"] = {}
    _metrics["total_latency_ms"] = 0.0


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Returns service health status, version, and uptime.",
)
async def health_check() -> HealthResponse:
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        uptime_seconds=round(time.time() - _start_time, 2),
    )


@router.get(
    "/ready",
    response_model=ReadinessResponse,
    summary="Readiness check",
    description="Verifies database, migrations, auth posture, and key-provider configuration.",
)
async def readiness_check(request: Request, response: Response) -> ReadinessResponse:
    settings = request.app.state.settings
    engine = request.app.state.database_engine
    checks: dict[str, object] = {}

    try:
        checks["database"] = {"ok": database_connects(engine)}
    except Exception as e:
        checks["database"] = {"ok": False, "error": str(e)}

    if settings.auto_create_tables:
        checks["migrations"] = {"ok": True, "mode": "auto_create_tables"}
    else:
        try:
            migration_info = migration_status(engine, settings.database_url)
            checks["migrations"] = {"ok": bool(migration_info["at_head"]), **migration_info}
        except Exception as e:
            checks["migrations"] = {"ok": False, "error": str(e)}

    auth_ok = settings.dev_auth_enabled or bool(
        settings.oidc_issuer and settings.oidc_audience and settings.oidc_jwks_url
    )
    checks["auth"] = {
        "ok": auth_ok and not (settings.is_production and settings.dev_auth_enabled),
        "mode": "dev" if settings.dev_auth_enabled else "oidc",
    }

    key_source = getattr(request.app.state, "master_key_source", "unknown")
    checks["key_provider"] = {
        "ok": (key_source == "aws-kms") if settings.is_production else key_source != "unknown",
        "source": key_source,
    }

    ready = all(bool(value.get("ok")) for value in checks.values() if isinstance(value, dict))
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
    )
