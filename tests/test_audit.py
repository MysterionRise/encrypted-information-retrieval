"""Tests for security audit logging."""

from __future__ import annotations

import logging

import pytest

from encrypted_ir.audit import AuditEventType, AuditLogger
from encrypted_ir.logging import set_correlation_id


class TestAuditEventTypes:
    """Verify event type enumeration."""

    def test_key_events_exist(self):
        assert AuditEventType.KEY_GENERATE.value == "key.generate"
        assert AuditEventType.KEY_ROTATE.value == "key.rotate"
        assert AuditEventType.KEY_DELETE.value == "key.delete"
        assert AuditEventType.KEY_ACCESS.value == "key.access"

    def test_auth_events_exist(self):
        assert AuditEventType.AUTH_LOGIN.value == "auth.login"
        assert AuditEventType.AUTH_FAILURE.value == "auth.failure"

    def test_search_events_exist(self):
        assert AuditEventType.SEARCH_KEYWORD.value == "search.keyword"
        assert AuditEventType.SEARCH_BOOLEAN.value == "search.boolean"
        assert AuditEventType.SEARCH_RANGE.value == "search.range"


class TestAuditLogger:
    """Verify audit log record structure and content."""

    @pytest.fixture(autouse=True)
    def setup_correlation(self):
        set_correlation_id("audit-test-corr")
        yield

    def test_log_returns_record(self):
        audit = AuditLogger()
        record = audit.log(AuditEventType.KEY_GENERATE, resource="key-001")

        assert record["audit"] is True
        assert record["event_type"] == "key.generate"
        assert record["success"] is True
        assert record["correlation_id"] == "audit-test-corr"
        assert record["resource"] == "key-001"

    def test_log_failure_event(self):
        audit = AuditLogger()
        record = audit.log(
            AuditEventType.AUTH_FAILURE,
            actor="user-123",
            success=False,
            details={"reason": "invalid_credentials"},
        )

        assert record["success"] is False
        assert record["actor"] == "user-123"
        assert record["details"]["reason"] == "invalid_credentials"

    def test_pii_redacted_in_resource(self):
        audit = AuditLogger()
        record = audit.log(
            AuditEventType.KEY_ACCESS,
            resource="alice@example.com",
        )
        assert "alice@example.com" not in record["resource"]
        assert "[REDACTED_EMAIL]" in record["resource"]

    def test_bytes_redacted_in_details(self):
        audit = AuditLogger()
        record = audit.log(
            AuditEventType.ENCRYPT,
            details={"plaintext": b"secret data"},
        )
        assert record["details"]["plaintext"] == "[REDACTED_BYTES]"

    def test_tenant_included(self):
        audit = AuditLogger()
        record = audit.log(
            AuditEventType.SEARCH_KEYWORD,
            tenant="acme-corp",
        )
        assert record["tenant"] == "acme-corp"


class TestAuditConvenienceMethods:
    """Verify convenience methods produce correct event types."""

    @pytest.fixture(autouse=True)
    def setup_correlation(self):
        set_correlation_id("conv-test")
        yield

    def test_key_generated(self):
        audit = AuditLogger()
        record = audit.key_generated("key-001", "deterministic", actor="admin")
        assert record["event_type"] == "key.generate"
        assert record["resource"] == "key-001"
        assert record["details"]["key_type"] == "deterministic"

    def test_key_rotated(self):
        audit = AuditLogger()
        record = audit.key_rotated("old-key", "new-key")
        assert record["event_type"] == "key.rotate"
        assert record["resource"] == "old-key"
        assert record["details"]["new_key_id"] == "new-key"

    def test_key_deleted(self):
        audit = AuditLogger()
        record = audit.key_deleted("key-002", actor="admin")
        assert record["event_type"] == "key.delete"
        assert record["resource"] == "key-002"

    def test_key_accessed(self):
        audit = AuditLogger()
        record = audit.key_accessed("key-003", "decrypt")
        assert record["event_type"] == "key.access"
        assert record["details"]["operation"] == "decrypt"

    def test_auth_failure(self):
        audit = AuditLogger()
        record = audit.auth_failure("baduser", "wrong password")
        assert record["event_type"] == "auth.failure"
        assert record["success"] is False
        assert record["actor"] == "baduser"

    def test_search_performed_keyword(self):
        audit = AuditLogger()
        record = audit.search_performed("keyword", tenant="corp-a", result_count=5)
        assert record["event_type"] == "search.keyword"
        assert record["tenant"] == "corp-a"
        assert record["details"]["result_count"] == 5

    def test_search_performed_boolean(self):
        audit = AuditLogger()
        record = audit.search_performed("boolean")
        assert record["event_type"] == "search.boolean"

    def test_search_performed_range(self):
        audit = AuditLogger()
        record = audit.search_performed("range")
        assert record["event_type"] == "search.range"

    def test_config_changed(self):
        audit = AuditLogger()
        record = audit.config_changed("log_level", details={"from": "INFO", "to": "DEBUG"})
        assert record["event_type"] == "config.change"
        assert record["details"]["setting"] == "log_level"
        assert record["details"]["from"] == "INFO"


class TestAuditLogOutput:
    """Verify audit records are written to the logger."""

    def test_audit_writes_to_logger(self):
        import io

        stream = io.StringIO()
        handler = logging.StreamHandler(stream)

        audit_logger = logging.getLogger("encrypted_ir.audit.test_output")
        audit_logger.handlers.clear()
        audit_logger.addHandler(handler)
        audit_logger.setLevel(logging.DEBUG)

        audit = AuditLogger(logger_name="encrypted_ir.audit.test_output")
        audit.key_generated("key-x", "searchable")

        output = stream.getvalue()
        # The output should contain the audit event JSON
        assert "key.generate" in output
        assert "key-x" in output
