"""Outermost ASGI middleware: request IDs, access logs, metrics, rejection audit and 500s.

``RequestContextMiddleware`` wraps the whole app, so every response passes through it,
including 500s from unhandled exceptions (which Starlette would otherwise turn into a response
outside all user middleware, with no request ID and no metrics). For each request it:

1. takes a safe ``X-Request-ID`` (or generates one), stores it in ``scope["state"]`` and binds
   it as the logging correlation ID, so every line logged while handling the request carries it;
2. resolves the route *template* (``/v1/documents/{doc_id}``), used for metrics labels, the
   access log and the audit resource, so concrete document IDs never appear in any of them;
3. applies the per-client-address rate limit (every path except ``/health``, before routing and
   before authentication, so unauthenticated requests are limited too);
4. adds ``X-Request-ID`` and ``X-Response-Time-Ms`` to the response;
5. turns an unhandled exception into the standard JSON 500 body, after logging its traceback;
6. after the response: records Prometheus metrics, writes one JSON access-log line, and counts
   and (rate-bounded) audits 401, 403 and 429 responses.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from starlette.concurrency import run_in_threadpool
from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import JSONResponse
from starlette.routing import Match
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from encrypted_ir.logging import bind_correlation_id, reset_correlation_id
from encrypted_ir.metrics import UNMATCHED_ROUTE, method_label

from .dependencies.rate_limiter import CLIENT_RATE_LIMIT, retry_after_header
from .middleware import error_body, sanitize_request_id

logger = logging.getLogger(__name__)
access_logger = logging.getLogger("encrypted_ir.api.access")

SYSTEM_TENANT_ID = "_system"

# Liveness probes must keep answering while a client is being throttled.
CLIENT_LIMIT_EXEMPT_PATHS = frozenset({"/health"})

# Rejections that are counted in /metrics and written (rate-bounded) to the audit log.
SECURITY_EVENTS = {
    401: ("auth.failure", "unauthenticated"),
    403: ("authz.failure", "forbidden"),
    429: ("rate_limit.exceeded", "rate_limited"),
}


def route_template(app: Any, scope: Scope) -> str:
    """Return the path template of the route that handles (or would handle) ``scope``.

    After routing, FastAPI records the matched route in ``scope["route"]``. Requests that never
    reached a route are matched against ``app.state.route_index``, built in ``create_app``; a
    route that matches the path but not the method (a 405) still names the template. Requests
    that match no route are labelled ``unmatched``.
    """
    matched = scope.get("route")
    if isinstance(getattr(matched, "path", None), str):
        return str(matched.path)
    partial: str | None = None
    for route in getattr(app.state, "route_index", ()):
        match, _ = route.matches(scope)
        if match == Match.FULL:
            return str(getattr(route, "path", UNMATCHED_ROUTE))
        if match == Match.PARTIAL and partial is None:
            partial = str(getattr(route, "path", UNMATCHED_ROUTE))
    return partial or UNMATCHED_ROUTE


class RequestContextMiddleware:
    """See the module docstring. Add it last so it is the outermost user middleware."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        fastapi_app = scope["app"]
        start = time.monotonic()
        request_id = sanitize_request_id(Headers(scope=scope).get("x-request-id"))
        state = scope.setdefault("state", {})
        state["request_id"] = request_id
        token = bind_correlation_id(request_id)
        status_code = 500
        response_started = False

        async def send_with_context(message: Message) -> None:
            nonlocal status_code, response_started
            if message["type"] == "http.response.start":
                response_started = True
                status_code = message["status"]
                headers = MutableHeaders(scope=message)
                headers["X-Request-ID"] = request_id
                headers["X-Response-Time-Ms"] = f"{(time.monotonic() - start) * 1000:.2f}"
            await send(message)

        try:
            try:
                retry_after = self._client_retry_after(fastapi_app, scope)
                if retry_after is None:
                    await self.app(scope, receive, send_with_context)
                else:
                    state["rejection_reason"] = "client_rate_limited"
                    response = JSONResponse(
                        status_code=429,
                        content=error_body("rate_limited", "Too many requests", request_id),
                        headers={"Retry-After": retry_after_header(retry_after)},
                    )
                    await response(scope, receive, send_with_context)
            except Exception:
                logger.exception(
                    "Unhandled error while handling request",
                    extra={
                        "route": route_template(fastapi_app, scope),
                        "method": method_label(scope["method"]),
                    },
                )
                status_code = 500
                if response_started:
                    raise
                response = JSONResponse(
                    status_code=500,
                    content=error_body("internal_error", "Internal server error", request_id),
                )
                await response(scope, receive, send_with_context)
            finally:
                route = route_template(fastapi_app, scope)
                await self._after_response(fastapi_app, scope, route, status_code, start)
        finally:
            reset_correlation_id(token)

    @staticmethod
    def _client_retry_after(app: Any, scope: Scope) -> float | None:
        """Apply the per-client limit; None if allowed, else seconds until it would be."""
        if scope["path"] in CLIENT_LIMIT_EXEMPT_PATHS:
            return None
        limiter = getattr(app.state, "rate_limiter", None)
        if limiter is None:
            return None
        client = scope.get("client")
        key = str(client[0]) if client else "unknown"
        result: float | None = limiter.try_acquire(key, CLIENT_RATE_LIMIT)
        return result

    async def _after_response(
        self, app: Any, scope: Scope, route: str, status_code: int, start: float
    ) -> None:
        state = scope["state"]
        seconds = time.monotonic() - start
        metrics = getattr(app.state, "metrics", None)
        if metrics is not None:
            metrics.observe_request(route, scope["method"], status_code, seconds)
        access_logger.info(
            "request",
            extra={
                "method": method_label(scope["method"]),
                "route": route,
                "status": status_code,
                "latency_ms": round(seconds * 1000, 2),
                "tenant_id": state.get("tenant_id"),
            },
        )
        if status_code in SECURITY_EVENTS:
            await self._audit_rejection(app, scope, route, status_code)

    @staticmethod
    async def _audit_rejection(app: Any, scope: Scope, route: str, status_code: int) -> None:
        """Count a 401/403/429 and write a rate-bounded audit row for it."""
        state = scope["state"]
        event_type, default_reason = SECURITY_EVENTS[status_code]
        reason = state.get("rejection_reason") or state.get("auth_failure") or default_reason
        metrics = getattr(app.state, "metrics", None)
        if metrics is not None:
            metrics.record_rejection(status_code, reason)

        limiter = getattr(app.state, "security_audit_limiter", None)
        if limiter is not None and not limiter.allow():
            if metrics is not None:
                metrics.record_security_audit_dropped()
            return

        try:
            await run_in_threadpool(
                app.state.document_service.record_audit_event,
                tenant_id=state.get("tenant_id") or SYSTEM_TENANT_ID,
                event_type=event_type,
                actor=state.get("actor") or "anonymous",
                success=False,
                resource=route,
                details={
                    "status": status_code,
                    "method": method_label(scope["method"]),
                    "reason": reason,
                },
                request_id=state["request_id"],
            )
        except Exception:
            logger.warning("Failed to audit a rejected request", exc_info=True)
