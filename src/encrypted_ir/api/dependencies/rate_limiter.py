"""Rate limiting dependency for the API."""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field

from fastapi import HTTPException, status


@dataclass
class RateLimitConfig:
    """Rate limit configuration for an operation type."""

    max_requests: int
    window_seconds: int = 60


# Default rate limits per operation type
DEFAULT_LIMITS: dict[str, RateLimitConfig] = {
    "document_ingest": RateLimitConfig(max_requests=60, window_seconds=60),
    "document_search": RateLimitConfig(max_requests=120, window_seconds=60),
    "document_get": RateLimitConfig(max_requests=120, window_seconds=60),
    "document_delete": RateLimitConfig(max_requests=60, window_seconds=60),
    "rag_retrieve": RateLimitConfig(max_requests=120, window_seconds=60),
}


@dataclass
class _BucketState:
    """Token bucket state for a single tenant+operation."""

    timestamps: list[float] = field(default_factory=list)


class RateLimiter:
    """In-memory sliding window rate limiter.

    Uses a per-tenant, per-operation sliding window counter. Route handlers run in FastAPI's
    thread pool, so the buckets are guarded by a lock. State is per process; in production,
    replace with a shared (for example Redis-backed) implementation.
    """

    def __init__(self, limits: dict[str, RateLimitConfig] | None = None):
        self._limits = limits or DEFAULT_LIMITS
        self._buckets: dict[str, _BucketState] = defaultdict(_BucketState)
        self._lock = threading.Lock()

    def check_limit(self, tenant_id: str, operation: str) -> None:
        """Check rate limit for a tenant+operation.

        Args:
            tenant_id: Tenant identifier.
            operation: Operation type (must be a key in the limits dict).

        Raises:
            HTTPException: 429 if rate limit exceeded.
        """
        config = self._limits.get(operation)
        if config is None:
            return  # No limit configured for this operation

        key = f"{tenant_id}:{operation}"
        with self._lock:
            bucket = self._buckets[key]
            now = time.monotonic()
            cutoff = now - config.window_seconds

            # Remove expired timestamps
            bucket.timestamps = [ts for ts in bucket.timestamps if ts > cutoff]

            if len(bucket.timestamps) >= config.max_requests:
                # Calculate retry-after
                oldest = bucket.timestamps[0]
                retry_after = int(oldest - cutoff) + 1
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded for {operation}. "
                    f"Max {config.max_requests} requests per {config.window_seconds}s.",
                    headers={"Retry-After": str(max(retry_after, 1))},
                )

            bucket.timestamps.append(now)

    def reset(self, tenant_id: str | None = None) -> None:
        """Reset rate limit counters.

        Args:
            tenant_id: Reset only this tenant's counters. If None, reset all.
        """
        with self._lock:
            if tenant_id is None:
                self._buckets.clear()
            else:
                keys_to_remove = [k for k in self._buckets if k.startswith(f"{tenant_id}:")]
                for k in keys_to_remove:
                    del self._buckets[k]


# Global rate limiter instance
_rate_limiter = RateLimiter()


async def get_rate_limiter() -> RateLimiter:
    """Get the global rate limiter instance."""
    return _rate_limiter


def set_rate_limiter(limiter: RateLimiter) -> None:
    """Replace the global rate limiter (for testing)."""
    global _rate_limiter
    _rate_limiter = limiter
