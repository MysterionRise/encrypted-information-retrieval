"""
Structured Logging Module

Provides structured JSON logging with correlation IDs and redaction for encrypted IR
operations. Every record passes through :func:`encrypted_ir.redaction.redact`, including the
formatted exception, so plaintext, keys and personal data are not written to the log.

In the API, the correlation ID is the request's ``X-Request-ID``: the request middleware sets
it for the duration of each request, so every line logged while handling a request carries it.
"""

from __future__ import annotations

import json
import logging
import sys
import threading
import uuid
from collections.abc import Iterable
from contextvars import ContextVar, Token
from datetime import UTC, datetime
from typing import IO, Any

from .redaction import redact, redact_text

# Context variable for correlation ID propagation across async boundaries
_correlation_id: ContextVar[str | None] = ContextVar("correlation_id", default=None)

_STANDARD_RECORD_ATTRS = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {
    "message",
    "asctime",
}


def get_correlation_id() -> str:
    """Get the current correlation ID, generating one if not set."""
    cid = _correlation_id.get()
    if cid is None:
        cid = uuid.uuid4().hex[:16]
        _correlation_id.set(cid)
    return cid


def set_correlation_id(correlation_id: str | None) -> None:
    """Set the correlation ID for the current context."""
    _correlation_id.set(correlation_id)


def current_correlation_id() -> str | None:
    """Return the current correlation ID without generating one."""
    return _correlation_id.get()


def bind_correlation_id(correlation_id: str | None) -> Token[str | None]:
    """Set the correlation ID for the current context and return a token to undo it."""
    return _correlation_id.set(correlation_id)


def reset_correlation_id(token: Token[str | None]) -> None:
    """Restore the correlation ID that was current before :func:`bind_correlation_id`."""
    _correlation_id.reset(token)


def new_correlation_id() -> str:
    """Generate and set a new correlation ID, returning it."""
    cid = uuid.uuid4().hex[:16]
    _correlation_id.set(cid)
    return cid


def redact_pii(text: str) -> str:
    """Redact key-like base64, card numbers, SSNs and email addresses from a string.

    Kept for compatibility; it is :func:`encrypted_ir.redaction.redact_text`.
    """
    return redact_text(text)


class StructuredFormatter(logging.Formatter):
    """JSON formatter that outputs structured log records.

    Each log line is a single JSON object with fields ``timestamp`` (UTC, ISO 8601 with
    milliseconds), ``level``, ``logger``, ``message`` and ``correlation_id`` (``null`` outside a
    request), plus any extra context passed via ``extra=`` and the formatted ``exception``. The
    whole object, exception text included, goes through :func:`encrypted_ir.redaction.redact`.
    """

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "correlation_id": current_correlation_id(),
        }

        # Merge extra context (anything not in standard LogRecord attrs)
        for attr, value in record.__dict__.items():
            if attr not in _STANDARD_RECORD_ATTRS:
                log_entry[attr] = value

        if record.exc_info and record.exc_info[0] is not None:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(redact(log_entry), default=str)

    def formatTime(  # noqa: N802
        self, record: logging.LogRecord, datefmt: str | None = None
    ) -> str:
        """UTC ISO-8601 timestamp with millisecond precision, e.g. 2026-10-28T09:15:02.123Z."""
        moment = datetime.fromtimestamp(record.created, tz=UTC)
        return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


class LoggingConfig:
    """Configure structured logging for the encrypted-ir library.

    Provides a simple interface to set up JSON-formatted logging with
    appropriate handlers, PII redaction, and correlation ID propagation.

    Example::

        config = LoggingConfig(level="INFO")
        config.setup()
        logger = config.get_logger("my_module")
        logger.info("Encryption complete", extra={"doc_id": "abc123"})
    """

    def __init__(
        self,
        level: str = "INFO",
        handler: logging.Handler | None = None,
        enable_console: bool = True,
        stream: IO[str] | None = None,
        extra_loggers: Iterable[str] = (),
    ):
        """Initialize logging configuration.

        Args:
            level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
            handler: Custom log handler. If None and enable_console is True,
                     uses a StreamHandler on ``stream``.
            enable_console: Whether to add a console handler if no custom
                          handler is provided.
            stream: Stream for the console handler (default: stdout).
            extra_loggers: Other loggers to route through the same JSON handler, such as
                ``uvicorn.error``. They stop propagating so lines are not written twice.
        """
        self.level = getattr(logging, level.upper(), logging.INFO)
        self._handler = handler
        self._enable_console = enable_console
        self._stream = stream
        self._extra_loggers = tuple(extra_loggers)
        self._configured = False
        self._lock = threading.Lock()

    def setup(self) -> None:
        """Apply the logging configuration to the encrypted_ir logger hierarchy."""
        with self._lock:
            if self._configured:
                return

            formatter = StructuredFormatter()
            handler = self._handler
            if handler is None and self._enable_console:
                handler = logging.StreamHandler(self._stream or sys.stdout)
            if handler is not None:
                handler.setFormatter(formatter)

            for name in ("encrypted_ir", *self._extra_loggers):
                logger = logging.getLogger(name)
                logger.setLevel(self.level)
                logger.handlers.clear()
                if handler is not None:
                    logger.addHandler(handler)
                if name != "encrypted_ir":
                    logger.propagate = False

            self._configured = True

    def get_logger(self, name: str) -> logging.Logger:
        """Get a child logger under the encrypted_ir namespace.

        Args:
            name: Logger name (will be prefixed with 'encrypted_ir.').

        Returns:
            Configured logger instance.
        """
        if not self._configured:
            self.setup()
        return logging.getLogger(f"encrypted_ir.{name}")
