"""Admin endpoints: health check and metrics."""

from __future__ import annotations

import time

from fastapi import APIRouter

from ..models.responses import HealthResponse, MetricsResponse

router = APIRouter(tags=["admin"])

_start_time: float = time.time()

# Simple in-memory metrics counters
_metrics = {
    "request_count": 0,
    "error_count": 0,
    "active_tenants": set(),
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
    _metrics["active_tenants"] = set()
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
