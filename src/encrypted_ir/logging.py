"""
Structured Logging Module

Provides structured JSON logging with correlation IDs,
PII redaction, and configurable log levels for encrypted IR operations.

Ensures that plaintext data and cryptographic keys are never logged,
supporting DORA Art. 17, PCI DSS 10.2.2, and NYDFS 500.06 compliance.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
import uuid
from contextvars import ContextVar
from typing import Any

# Context variable for correlation ID propagation across async boundaries
_correlation_id: ContextVar[str | None] = ContextVar("correlation_id", default=None)

# Patterns that indicate sensitive data - compiled once at module load
_PII_PATTERNS = [
    (re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b"), "[REDACTED_KEY]"),
    (re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "[REDACTED_CARD]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_SSN]"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"), "[REDACTED_EMAIL]"),
]

# Keys whose values should always be redacted in log output
_SENSITIVE_KEYS = frozenset(
    {
        "key",
        "keys",
        "secret",
        "password",
        "token",
        "plaintext",
        "master_key",
        "encryption_key",
        "search_key",
        "private_key",
        "secret_key",
        "credentials",
        "api_key",
    }
)


def get_correlation_id() -> str:
    """Get the current correlation ID, generating one if not set."""
    cid = _correlation_id.get()
    if cid is None:
        cid = uuid.uuid4().hex[:16]
        _correlation_id.set(cid)
    return cid


def set_correlation_id(correlation_id: str) -> None:
    """Set the correlation ID for the current context."""
    _correlation_id.set(correlation_id)


def new_correlation_id() -> str:
    """Generate and set a new correlation ID, returning it."""
    cid = uuid.uuid4().hex[:16]
    _correlation_id.set(cid)
    return cid


def redact_pii(text: str) -> str:
    """Redact PII patterns from a string.

    Scans for credit card numbers, SSNs, email addresses, and
    base64-encoded keys/secrets.

    Args:
        text: Input string to redact.

    Returns:
        String with sensitive patterns replaced by redaction markers.
    """
    for pattern, replacement in _PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _redact_value(key: str, value: Any) -> Any:
    """Redact a value if its key indicates sensitivity."""
    if isinstance(key, str) and key.lower() in _SENSITIVE_KEYS:
        return "[REDACTED]"
    if isinstance(value, str):
        return redact_pii(value)
    return value


def _sanitize_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Recursively sanitize a dictionary, redacting sensitive values."""
    sanitized: dict[str, Any] = {}
    for k, v in data.items():
        if isinstance(v, dict):
            sanitized[k] = _sanitize_dict(v)
        elif isinstance(v, (list, tuple)):
            sanitized[k] = [
                _sanitize_dict(item) if isinstance(item, dict) else _redact_value(k, item)
                for item in v
            ]
        else:
            sanitized[k] = _redact_value(k, v)
    return sanitized


class StructuredFormatter(logging.Formatter):
    """JSON formatter that outputs structured log records.

    Each log line is a single JSON object with fields:
        timestamp, level, logger, message, correlation_id,
        plus any extra context passed via the `extra` kwarg.
    """

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt or "%Y-%m-%dT%H:%M:%S.%fZ"),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_pii(record.getMessage()),
            "correlation_id": get_correlation_id(),
        }

        # Merge extra context (anything not in standard LogRecord attrs)
        standard_attrs = set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__)
        for attr, value in record.__dict__.items():
            if attr not in standard_attrs and attr not in ("message", "msg", "args"):
                log_entry[attr] = value

        # Sanitize the whole entry
        log_entry = _sanitize_dict(log_entry)

        if record.exc_info and record.exc_info[0] is not None:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, default=str)

    def formatTime(  # noqa: N802
        self, record: logging.LogRecord, datefmt: str | None = None
    ) -> str:
        """ISO-8601 timestamp with millisecond precision."""
        ct = self.converter(record.created)
        if datefmt:
            try:
                s = time.strftime(datefmt, ct)
            except (ValueError, TypeError):
                s = time.strftime("%Y-%m-%dT%H:%M:%S", ct)
        else:
            s = time.strftime("%Y-%m-%dT%H:%M:%S", ct)
        return f"{s}.{int(record.msecs):03d}Z"


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
    ):
        """Initialize logging configuration.

        Args:
            level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
            handler: Custom log handler. If None and enable_console is True,
                     uses StreamHandler to stderr.
            enable_console: Whether to add a console handler if no custom
                          handler is provided.
        """
        self.level = getattr(logging, level.upper(), logging.INFO)
        self._handler = handler
        self._enable_console = enable_console
        self._configured = False
        self._lock = threading.Lock()

    def setup(self) -> None:
        """Apply the logging configuration to the encrypted_ir logger hierarchy."""
        with self._lock:
            if self._configured:
                return

            root_logger = logging.getLogger("encrypted_ir")
            root_logger.setLevel(self.level)
            root_logger.handlers.clear()

            formatter = StructuredFormatter()

            if self._handler is not None:
                self._handler.setFormatter(formatter)
                root_logger.addHandler(self._handler)
            elif self._enable_console:
                console = logging.StreamHandler()
                console.setFormatter(formatter)
                root_logger.addHandler(console)

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
