"""ASGI middleware and helpers for request limits, request IDs and security-event auditing."""

from __future__ import annotations

import re
import time
import uuid
from collections.abc import Callable

from fastapi import HTTPException, status
from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .dependencies.rate_limiter import RateLimitConfig, RateLimiter

REQUEST_ID_PATTERN = r"[A-Za-z0-9._-]{1,64}"

# Starlette deprecated HTTP_413_REQUEST_ENTITY_TOO_LARGE in favour of a name older releases lack.
HTTP_413_CONTENT_TOO_LARGE = 413


def sanitize_request_id(value: str | None) -> str:
    """Return ``value`` if it is a safe request ID, otherwise a fresh UUID.

    A safe ID is 1 to 64 characters of ``[A-Za-z0-9._-]``, so a client cannot inject log
    lines, markup or oversized values through ``X-Request-ID``.
    """
    if value is not None and re.fullmatch(REQUEST_ID_PATTERN, value):
        return value
    return str(uuid.uuid4())


def error_body(error: str, message: str, request_id: str) -> dict[str, object]:
    """The standard JSON error body used by every handler."""
    return {"error": error, "message": message, "request_id": request_id, "details": []}


class RequestBodyTooLargeError(HTTPException):
    """Raised from the wrapped ``receive`` when a streamed body passes the limit."""

    def __init__(self) -> None:
        super().__init__(
            status_code=HTTP_413_CONTENT_TOO_LARGE,
            detail="Request body too large",
        )


class BodySizeLimitMiddleware:
    """Reject request bodies larger than ``max_body_bytes``.

    A declared ``Content-Length`` is checked before the app runs: 400 if it is not a single
    non-negative integer, 413 if it is over the limit. Bodies without a length (chunked) are
    counted as they stream; passing the limit raises :class:`RequestBodyTooLargeError` inside
    the app, which FastAPI turns into a 413 before the handler runs.
    """

    def __init__(self, app: ASGIApp, max_body_bytes: int):
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        lengths = set(Headers(scope=scope).getlist("content-length"))
        if lengths:
            value = lengths.pop() if len(lengths) == 1 else ""
            if not (value.isascii() and value.isdigit()):
                await self._reject(scope, receive, send, status.HTTP_400_BAD_REQUEST)
                return
            if int(value) > self.max_body_bytes:
                await self._reject(scope, receive, send, HTTP_413_CONTENT_TOO_LARGE)
                return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_body_bytes:
                    raise RequestBodyTooLargeError()
            return message

        await self.app(scope, limited_receive, send)

    @staticmethod
    async def _reject(scope: Scope, receive: Receive, send: Send, status_code: int) -> None:
        request_id = scope.get("state", {}).get("request_id", "unknown")
        if status_code == HTTP_413_CONTENT_TOO_LARGE:
            body = error_body("request_too_large", "Request body too large", request_id)
        else:
            body = error_body("bad_request", "Invalid Content-Length header", request_id)
        await JSONResponse(status_code=status_code, content=body)(scope, receive, send)


class SecurityAuditLimiter:
    """Bound the audit rows written for rejected requests, per source and in total.

    Rejected requests (401, 403, 429) are cheap to generate, so their audit rows are limited to
    keep a flood from filling the audit table: at most ``per_source`` rows per window for each
    source (the authenticated tenant, or the client address when unauthenticated) and at most
    ``total`` rows per window for the process. Requests over either bound are still counted in
    ``/metrics``.
    """

    def __init__(
        self,
        per_source: tuple[int, float] = (20, 60.0),
        total: tuple[int, float] = (120, 60.0),
        max_sources: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._limiter = RateLimiter(
            {"source": RateLimitConfig(*per_source), "total": RateLimitConfig(*total)},
            max_keys=max_sources,
            clock=clock,
        )

    def allow(self, source: str) -> str | None:
        """None if a row for ``source`` may be written, else the bound that dropped it."""
        if self._limiter.try_acquire(source, "source") is not None:
            return "per_source"
        if self._limiter.try_acquire("*", "total") is not None:
            return "total"
        return None
