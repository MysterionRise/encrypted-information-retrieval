"""Rate limiting for the API.

Limits are enforced in memory, per process. Several uvicorn workers or API replicas each keep
their own counters, so the effective limit is the configured one times the number of
processes; a multi-replica deployment needs an external limiter in front of the API.

The limiter uses GCRA (the generic cell rate algorithm, an exact form of a token bucket): each
key keeps one timestamp, the *theoretical arrival time*, so memory is constant per key and the
``Retry-After`` value is exact. A limit of N requests per window allows a burst of N, then one
request every ``window / N`` seconds.

Buckets live in one LRU per operation. A bucket that has fully refilled carries no state and is
dropped; each operation also keeps at most ``max_keys`` buckets, dropping the least recently
used one beyond that. Dropping a bucket can only give that key a fresh allowance, so a flood of
new tenant IDs or client addresses cannot grow memory without bound.
"""

from __future__ import annotations

import math
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from fastapi import HTTPException, Request, status

from encrypted_ir.settings import (
    CLIENT_RATE_LIMIT,
    DEFAULT_RATE_LIMIT_MAX_KEYS,
    DEFAULT_RATE_LIMITS,
)


@dataclass(frozen=True)
class RateLimitConfig:
    """Rate limit configuration for an operation type."""

    max_requests: int
    window_seconds: float = 60

    @property
    def interval(self) -> float:
        """Seconds of allowance one request uses."""
        return self.window_seconds / self.max_requests


DEFAULT_LIMITS: dict[str, RateLimitConfig] = {
    operation: RateLimitConfig(max_requests, window)
    for operation, (max_requests, window) in DEFAULT_RATE_LIMITS.items()
}


class RateLimiter:
    """In-memory GCRA rate limiter with bounded state. See the module docstring.

    Args:
        limits: Limits per operation. Operations without a limit are not limited. Defaults to
            :data:`DEFAULT_LIMITS`.
        max_keys: Most buckets kept per operation.
        clock: Monotonic clock, injectable for tests.
    """

    def __init__(
        self,
        limits: Mapping[str, RateLimitConfig] | None = None,
        *,
        max_keys: int = DEFAULT_RATE_LIMIT_MAX_KEYS,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._limits = dict(DEFAULT_LIMITS if limits is None else limits)
        self._max_keys = max_keys
        self._clock = clock
        self._buckets: dict[str, OrderedDict[str, float]] = {
            operation: OrderedDict() for operation in self._limits
        }
        self._lock = threading.Lock()

    @classmethod
    def from_limits(
        cls, limits: Mapping[str, tuple[int, int]], *, max_keys: int = DEFAULT_RATE_LIMIT_MAX_KEYS
    ) -> RateLimiter:
        """Build a limiter from ``(max_requests, window_seconds)`` pairs, as in settings."""
        return cls(
            {op: RateLimitConfig(n, window) for op, (n, window) in limits.items()},
            max_keys=max_keys,
        )

    def try_acquire(self, key: str, operation: str) -> float | None:
        """Take one request from ``key``'s allowance.

        Returns None if the request is allowed, otherwise the seconds until it would be.
        """
        config = self._limits.get(operation)
        if config is None:
            return None

        with self._lock:
            now = self._clock()
            buckets = self._buckets[operation]
            self._evict_refilled(buckets, now)

            arrival = max(buckets.get(key, now), now) + config.interval
            allowed_at = arrival - config.window_seconds
            if allowed_at > now:
                buckets.move_to_end(key)
                return allowed_at - now

            buckets[key] = arrival
            buckets.move_to_end(key)
            while len(buckets) > self._max_keys:
                buckets.popitem(last=False)
            return None

    def check_limit(self, tenant_id: str, operation: str) -> None:
        """Raise 429 with ``Retry-After`` if ``tenant_id`` is over the ``operation`` limit."""
        retry_after = self.try_acquire(tenant_id, operation)
        if retry_after is not None:
            config = self._limits[operation]
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded for {operation}. "
                f"Max {config.max_requests} requests per {config.window_seconds:g}s.",
                headers={"Retry-After": retry_after_header(retry_after)},
            )

    def bucket_count(self, operation: str | None = None) -> int:
        """Number of buckets held, for one operation or in total."""
        with self._lock:
            if operation is not None:
                return len(self._buckets.get(operation, ()))
            return sum(len(buckets) for buckets in self._buckets.values())

    def reset(self, key: str | None = None) -> None:
        """Forget all buckets, or only ``key``'s."""
        with self._lock:
            for buckets in self._buckets.values():
                if key is None:
                    buckets.clear()
                else:
                    buckets.pop(key, None)

    @staticmethod
    def _evict_refilled(buckets: OrderedDict[str, float], now: float) -> None:
        # The least recently used buckets are at the front; drop those that have fully refilled.
        while buckets:
            oldest_key = next(iter(buckets))
            if buckets[oldest_key] > now:
                break
            del buckets[oldest_key]


def retry_after_header(seconds: float) -> str:
    """Whole seconds for a ``Retry-After`` header, at least 1."""
    return str(max(1, math.ceil(seconds)))


async def get_rate_limiter(request: Request) -> RateLimiter:
    """The app's rate limiter (``app.state.rate_limiter``). Async: it never blocks."""
    limiter: RateLimiter = request.app.state.rate_limiter
    return limiter


__all__ = [
    "CLIENT_RATE_LIMIT",
    "DEFAULT_LIMITS",
    "RateLimitConfig",
    "RateLimiter",
    "get_rate_limiter",
    "retry_after_header",
]
