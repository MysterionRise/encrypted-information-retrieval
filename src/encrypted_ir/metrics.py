"""
Prometheus Metrics Module

Request and security metrics for the Encrypted IR API, served on ``GET /metrics`` in the
Prometheus text exposition format.

Every label has a bounded set of values: routes are FastAPI route *templates*
(``/v1/documents/{doc_id}``, never a concrete document ID) or ``unmatched``; methods are the
standard HTTP verbs or ``OTHER``; rejection reasons are fixed codes from the auth layer. Each
app gets its own registry, so metrics are per process: run one uvicorn worker per container,
or aggregate at the scraper.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import cast

try:
    from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest
except ImportError as _err:  # pragma: no cover
    raise ImportError(
        "prometheus_client is required for metrics support. "
        "Install with: pip install prometheus-client"
    ) from _err

HTTP_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
UNMATCHED_ROUTE = "unmatched"

DURATION_BUCKETS = (0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)


def method_label(method: str) -> str:
    """Map an HTTP method to a bounded label value."""
    upper = method.upper()
    return upper if upper in HTTP_METHODS else "OTHER"


class EncryptionMetrics:
    """Prometheus metrics for one API process.

    Args:
        registry: Optional ``CollectorRegistry``. If None, a new isolated registry is created.
        namespace: Metric name prefix (default: ``encrypted_ir``).
    """

    def __init__(
        self,
        registry: CollectorRegistry | None = None,
        namespace: str = "encrypted_ir",
    ):
        self.registry = registry or CollectorRegistry()
        self._namespace = namespace

        self.http_requests_total = Counter(
            f"{namespace}_http_requests_total",
            "HTTP requests by route template, method and status code",
            ["route", "method", "status"],
            registry=self.registry,
        )
        self.http_request_duration_seconds = Histogram(
            f"{namespace}_http_request_duration_seconds",
            "HTTP request latency in seconds by route template and method",
            ["route", "method"],
            buckets=DURATION_BUCKETS,
            registry=self.registry,
        )
        self.auth_rejections_total = Counter(
            f"{namespace}_auth_rejections_total",
            "401, 403 and 429 responses by status code and reason",
            ["status", "reason"],
            registry=self.registry,
        )
        self.security_audit_dropped_total = Counter(
            f"{namespace}_security_audit_dropped_total",
            "Rejected requests not written to the audit log because of its rate bound",
            registry=self.registry,
        )
        self.key_cache_tenants = Gauge(
            f"{namespace}_key_cache_tenants",
            "Tenants whose key managers are cached in this process",
            registry=self.registry,
        )

    def observe_request(self, route: str, method: str, status: int, seconds: float) -> None:
        """Count one finished request and record its latency."""
        method = method_label(method)
        self.http_requests_total.labels(route=route, method=method, status=str(status)).inc()
        self.http_request_duration_seconds.labels(route=route, method=method).observe(seconds)

    def record_rejection(self, status: int, reason: str) -> None:
        """Count a 401, 403 or 429 response."""
        self.auth_rejections_total.labels(status=str(status), reason=reason).inc()

    def record_security_audit_dropped(self) -> None:
        """Count a rejection that was not audited because of the audit rate bound."""
        self.security_audit_dropped_total.inc()

    def track_key_cache(self, size: Callable[[], int]) -> None:
        """Report the key-manager cache size by calling ``size`` at scrape time."""
        self.key_cache_tenants.set_function(lambda: float(size()))

    def collect(self) -> bytes:
        """Return the registry in Prometheus text exposition format."""
        return cast(bytes, generate_latest(self.registry))
