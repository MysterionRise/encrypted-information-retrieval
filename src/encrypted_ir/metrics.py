"""
Prometheus Metrics Module

Provides application-level metrics for encrypted IR operations using
the Prometheus client library. Tracks request counts, latency histograms,
error rates, key cache hit rates, and active connections.

Designed for integration with Prometheus/Grafana monitoring stacks.
"""

from __future__ import annotations
from __future__ import annotations

import time
from collections.abc import Generator
from contextlib import contextmanager

try:
    from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest
except ImportError as _err:  # pragma: no cover
    raise ImportError(
        "prometheus_client is required for metrics support. "
        "Install with: pip install prometheus-client"
    ) from _err


class EncryptionMetrics:
    """Prometheus metrics collector for encrypted IR operations.

    Provides counters, histograms, and gauges covering:
    - Request counts by operation and status
    - Latency histograms by operation
    - Error counts by operation and error type
    - Key cache hit/miss rates
    - Active connections gauge

    Args:
        registry: Optional prometheus_client.CollectorRegistry.
                  If None, creates a new isolated registry (useful for testing).
        namespace: Metric name prefix (default: "encrypted_ir").
    """

    def __init__(
        self,
        registry: CollectorRegistry | None = None,
        namespace: str = "encrypted_ir",
    ):
        self.registry = registry or CollectorRegistry()
        self._namespace = namespace

        # --- Counters ---

        self.request_total = Counter(
            f"{namespace}_requests_total",
            "Total number of encryption/decryption requests",
            ["operation", "status"],
            registry=self.registry,
        )

        self.errors_total = Counter(
            f"{namespace}_errors_total",
            "Total number of errors by operation and type",
            ["operation", "error_type"],
            registry=self.registry,
        )

        self.key_operations_total = Counter(
            f"{namespace}_key_operations_total",
            "Total key management operations",
            ["operation"],
            registry=self.registry,
        )

        self.search_queries_total = Counter(
            f"{namespace}_search_queries_total",
            "Total search queries executed",
            ["query_type"],
            registry=self.registry,
        )

        # --- Histograms ---

        self.request_duration_seconds = Histogram(
            f"{namespace}_request_duration_seconds",
            "Request latency in seconds",
            ["operation"],
            buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
            registry=self.registry,
        )

        # --- Gauges ---

        self.active_connections = Gauge(
            f"{namespace}_active_connections",
            "Number of active client connections",
            registry=self.registry,
        )

        self.key_cache_hit_ratio = Gauge(
            f"{namespace}_key_cache_hit_ratio",
            "Key cache hit ratio (0.0 - 1.0)",
            registry=self.registry,
        )

        self.key_cache_size = Gauge(
            f"{namespace}_key_cache_size",
            "Number of keys currently in cache",
            registry=self.registry,
        )

        # Internal counters for hit ratio calculation
        self._cache_hits = 0
        self._cache_misses = 0

    # --- Recording helpers ---

    def record_request(self, operation: str, status: str = "success") -> None:
        """Record a completed request.

        Args:
            operation: Operation name (e.g. "encrypt", "decrypt", "search").
            status: Outcome status ("success" or "error").
        """
        self.request_total.labels(operation=operation, status=status).inc()

    def record_error(self, operation: str, error_type: str) -> None:
        """Record an error.

        Args:
            operation: Operation that failed.
            error_type: Error classification (e.g. "invalid_key", "decryption_failed").
        """
        self.errors_total.labels(operation=operation, error_type=error_type).inc()
        self.request_total.labels(operation=operation, status="error").inc()

    def record_key_operation(self, operation: str) -> None:
        """Record a key management operation.

        Args:
            operation: Key operation type (e.g. "create", "rotate", "delete", "get").
        """
        self.key_operations_total.labels(operation=operation).inc()

    def record_search(self, query_type: str = "keyword") -> None:
        """Record a search query.

        Args:
            query_type: Type of search ("keyword", "boolean", "range").
        """
        self.search_queries_total.labels(query_type=query_type).inc()

    def record_cache_hit(self) -> None:
        """Record a key cache hit and update the hit ratio gauge."""
        self._cache_hits += 1
        self._update_cache_ratio()

    def record_cache_miss(self) -> None:
        """Record a key cache miss and update the hit ratio gauge."""
        self._cache_misses += 1
        self._update_cache_ratio()

    def set_cache_size(self, size: int) -> None:
        """Update the key cache size gauge.

        Args:
            size: Current number of cached keys.
        """
        self.key_cache_size.set(size)

    def _update_cache_ratio(self) -> None:
        """Recalculate and set the cache hit ratio gauge."""
        total = self._cache_hits + self._cache_misses
        if total > 0:
            self.key_cache_hit_ratio.set(self._cache_hits / total)

    @contextmanager
    def track_duration(self, operation: str) -> Generator[None, None, None]:
        """Context manager that measures operation duration.

        Records the elapsed time in the request_duration_seconds histogram
        and increments the request counter with appropriate status.

        Args:
            operation: Operation name for labeling.

        Example::

            with metrics.track_duration("encrypt"):
                result = encryptor.encrypt(data)
        """
        start = time.monotonic()
        try:
            yield
            elapsed = time.monotonic() - start
            self.request_duration_seconds.labels(operation=operation).observe(elapsed)
            self.record_request(operation, "success")
        except Exception:
            elapsed = time.monotonic() - start
            self.request_duration_seconds.labels(operation=operation).observe(elapsed)
            self.record_request(operation, "error")
            raise

    @contextmanager
    def track_connection(self) -> Generator[None, None, None]:
        """Context manager that tracks active connections.

        Increments the gauge on entry and decrements on exit.
        """
        self.active_connections.inc()
        try:
            yield
        finally:
            self.active_connections.dec()

    def collect(self) -> bytes:
        """Generate Prometheus exposition format output.

        Returns:
            Bytes in Prometheus text exposition format, suitable for
            serving on a /metrics endpoint.
        """
        return generate_latest(self.registry)
