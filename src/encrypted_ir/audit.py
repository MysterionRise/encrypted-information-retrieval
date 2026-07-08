"""
Security Audit Logging Module

Provides structured audit logging for security-relevant events in the
encrypted IR system. Covers key operations, authentication events,
search queries, and configuration changes.

Supports DORA Art. 17 continuous monitoring, PCI DSS 10.2.2 automated
audit trails, and NYDFS 500.06 audit trail requirements.
"""

from __future__ import annotations

import json
import logging
import time
from enum import Enum
from typing import Any

from .logging import StructuredFormatter, get_correlation_id, redact_pii


class AuditEventType(Enum):
    """Categories of auditable security events."""

    # Key management
    KEY_GENERATE = "key.generate"
    KEY_ROTATE = "key.rotate"
    KEY_DELETE = "key.delete"
    KEY_ACCESS = "key.access"
    KEY_EXPORT = "key.export"
    KEY_IMPORT = "key.import"
    KEY_WRAP = "key.wrap"
    KEY_UNWRAP = "key.unwrap"

    # Authentication
    AUTH_LOGIN = "auth.login"
    AUTH_LOGOUT = "auth.logout"
    AUTH_TOKEN_REFRESH = "auth.token_refresh"  # noqa: S105
    AUTH_FAILURE = "auth.failure"

    # Authorization
    AUTHZ_DENIED = "authz.denied"

    # Encryption operations
    ENCRYPT = "crypto.encrypt"
    DECRYPT = "crypto.decrypt"

    # Search operations
    SEARCH_KEYWORD = "search.keyword"
    SEARCH_BOOLEAN = "search.boolean"
    SEARCH_RANGE = "search.range"

    # Configuration
    CONFIG_CHANGE = "config.change"


class AuditLogger:
    """Structured audit logger for security events.

    Writes audit records as structured JSON to a dedicated audit logger,
    separate from application logs. Each record includes:
    - event type and timestamp
    - correlation ID for request tracing
    - actor (user/service identity)
    - outcome (success/failure)
    - sanitized details (never contains plaintext or keys)

    Args:
        logger_name: Name for the audit logger
                     (default: "encrypted_ir.audit").
    """

    def __init__(self, logger_name: str = "encrypted_ir.audit"):
        self._logger = logging.getLogger(logger_name)
        # Only add handler if none exist yet (avoid duplicate handlers)
        if not self._logger.handlers and not self._logger.parent.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(StructuredFormatter())
            self._logger.addHandler(handler)
        self._logger.setLevel(logging.INFO)

    def log(
        self,
        event_type: AuditEventType,
        *,
        actor: str = "system",
        success: bool = True,
        resource: str = "",
        details: dict[str, Any] | None = None,
        tenant: str = "",
    ) -> dict[str, Any]:
        """Record an audit event.

        Args:
            event_type: The type of security event.
            actor: Identity of the user or service performing the action.
            success: Whether the operation succeeded.
            resource: The resource being acted upon (e.g. key_id, doc_id).
            details: Additional context (will be PII-redacted).
            tenant: Tenant identifier for multi-tenant deployments.

        Returns:
            The sanitized audit record dict (useful for testing).
        """
        record: dict[str, Any] = {
            "audit": True,
            "event_type": event_type.value,
            "timestamp": time.time(),
            "correlation_id": get_correlation_id(),
            "actor": actor,
            "success": success,
            "resource": redact_pii(resource) if resource else "",
            "tenant": tenant,
        }

        if details:
            sanitized: dict[str, Any] = {}
            for k, v in details.items():
                if isinstance(v, str):
                    sanitized[k] = redact_pii(v)
                elif isinstance(v, bytes):
                    sanitized[k] = "[REDACTED_BYTES]"
                else:
                    sanitized[k] = v
            record["details"] = sanitized

        level = logging.INFO if success else logging.WARNING
        self._logger.log(level, json.dumps(record, default=str))

        return record

    # --- Convenience methods for common events ---

    def key_generated(self, key_id: str, key_type: str, actor: str = "system") -> dict[str, Any]:
        """Log a key generation event."""
        return self.log(
            AuditEventType.KEY_GENERATE,
            actor=actor,
            resource=key_id,
            details={"key_type": key_type},
        )

    def key_rotated(
        self, old_key_id: str, new_key_id: str, actor: str = "system"
    ) -> dict[str, Any]:
        """Log a key rotation event."""
        return self.log(
            AuditEventType.KEY_ROTATE,
            actor=actor,
            resource=old_key_id,
            details={"new_key_id": new_key_id},
        )

    def key_deleted(self, key_id: str, actor: str = "system") -> dict[str, Any]:
        """Log a key deletion event."""
        return self.log(
            AuditEventType.KEY_DELETE,
            actor=actor,
            resource=key_id,
        )

    def key_accessed(self, key_id: str, operation: str, actor: str = "system") -> dict[str, Any]:
        """Log a key access event."""
        return self.log(
            AuditEventType.KEY_ACCESS,
            actor=actor,
            resource=key_id,
            details={"operation": operation},
        )

    def auth_failure(self, actor: str, reason: str) -> dict[str, Any]:
        """Log an authentication failure."""
        return self.log(
            AuditEventType.AUTH_FAILURE,
            actor=actor,
            success=False,
            details={"reason": reason},
        )

    def search_performed(
        self,
        query_type: str,
        actor: str = "system",
        tenant: str = "",
        result_count: int = 0,
    ) -> dict[str, Any]:
        """Log a search operation."""
        event_map = {
            "keyword": AuditEventType.SEARCH_KEYWORD,
            "boolean": AuditEventType.SEARCH_BOOLEAN,
            "range": AuditEventType.SEARCH_RANGE,
        }
        event = event_map.get(query_type, AuditEventType.SEARCH_KEYWORD)
        return self.log(
            event,
            actor=actor,
            tenant=tenant,
            details={"query_type": query_type, "result_count": result_count},
        )

    def config_changed(
        self, setting: str, actor: str = "system", details: dict | None = None
    ) -> dict[str, Any]:
        """Log a configuration change."""
        d = {"setting": setting}
        if details:
            d.update(details)
        return self.log(
            AuditEventType.CONFIG_CHANGE,
            actor=actor,
            details=d,
        )
