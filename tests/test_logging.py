"""Tests for structured logging and PII redaction."""

from __future__ import annotations

import json
import logging

from encrypted_ir.logging import (
    LoggingConfig,
    StructuredFormatter,
    get_correlation_id,
    new_correlation_id,
    redact_pii,
    set_correlation_id,
)


class TestPIIRedaction:
    """Verify PII is never leaked into log output."""

    def test_redacts_credit_card_numbers(self):
        text = "Card: 4111 1111 1111 1111"
        result = redact_pii(text)
        assert "4111" not in result
        assert "[REDACTED_CARD]" in result

    def test_redacts_ssn(self):
        text = "SSN: 123-45-6789"
        result = redact_pii(text)
        assert "123-45-6789" not in result
        assert "[REDACTED_SSN]" in result

    def test_redacts_email(self):
        text = "Contact: alice@example.com"
        result = redact_pii(text)
        assert "alice@example.com" not in result
        assert "[REDACTED_EMAIL]" in result

    def test_redacts_base64_keys(self):
        # 44-char base64 string (256-bit key)
        key = "A" * 44
        text = f"Key is {key}"
        result = redact_pii(text)
        assert key not in result
        assert "[REDACTED_KEY]" in result

    def test_preserves_normal_text(self):
        text = "Encryption of document doc-123 completed"
        assert redact_pii(text) == text

    def test_multiple_patterns_in_one_string(self):
        text = "User alice@test.com used card 4111 1111 1111 1111"
        result = redact_pii(text)
        assert "alice@test.com" not in result
        assert "4111" not in result


class TestCorrelationID:
    """Verify correlation ID propagation."""

    def test_get_generates_if_unset(self):
        # Reset to force generation
        set_correlation_id(None)
        cid = get_correlation_id()
        assert cid is not None
        assert len(cid) == 16

    def test_set_and_get(self):
        set_correlation_id("test-corr-id-01")
        assert get_correlation_id() == "test-corr-id-01"

    def test_new_generates_fresh_id(self):
        old = get_correlation_id()
        new = new_correlation_id()
        assert new != old
        assert get_correlation_id() == new


class TestStructuredFormatter:
    """Verify JSON log output format."""

    def _make_record(self, msg: str, level: int = logging.INFO, **extra) -> logging.LogRecord:
        record = logging.LogRecord(
            name="encrypted_ir.test",
            level=level,
            pathname="test.py",
            lineno=1,
            msg=msg,
            args=(),
            exc_info=None,
        )
        for k, v in extra.items():
            setattr(record, k, v)
        return record

    def test_output_is_valid_json(self):
        fmt = StructuredFormatter()
        record = self._make_record("test message")
        output = fmt.format(record)
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_contains_required_fields(self):
        set_correlation_id("fmt-test-id")
        fmt = StructuredFormatter()
        record = self._make_record("test message")
        parsed = json.loads(fmt.format(record))

        assert parsed["level"] == "INFO"
        assert parsed["logger"] == "encrypted_ir.test"
        assert parsed["message"] == "test message"
        assert parsed["correlation_id"] == "fmt-test-id"
        assert "timestamp" in parsed

    def test_redacts_pii_in_message(self):
        fmt = StructuredFormatter()
        record = self._make_record("User alice@example.com logged in")
        parsed = json.loads(fmt.format(record))
        assert "alice@example.com" not in parsed["message"]
        assert "[REDACTED_EMAIL]" in parsed["message"]

    def test_redacts_sensitive_extra_keys(self):
        fmt = StructuredFormatter()
        record = self._make_record("Key access", password="supersecret")
        parsed = json.loads(fmt.format(record))
        assert parsed.get("password") == "[REDACTED]"

    def test_includes_exception_info(self):
        fmt = StructuredFormatter()
        try:
            raise ValueError("test error")
        except ValueError:
            import sys

            record = self._make_record("error occurred", level=logging.ERROR)
            record.exc_info = sys.exc_info()

        parsed = json.loads(fmt.format(record))
        assert "exception" in parsed
        assert "ValueError" in parsed["exception"]

    def test_extra_context_included(self):
        fmt = StructuredFormatter()
        record = self._make_record("op done", operation="encrypt", doc_id="doc-123")
        parsed = json.loads(fmt.format(record))
        assert parsed["operation"] == "encrypt"
        assert parsed["doc_id"] == "doc-123"


class TestLoggingConfig:
    """Verify LoggingConfig setup and logger creation."""

    def test_setup_creates_handler(self):
        config = LoggingConfig(level="DEBUG")
        config.setup()
        logger = logging.getLogger("encrypted_ir")
        assert len(logger.handlers) > 0
        assert logger.level == logging.DEBUG
        # Cleanup
        logger.handlers.clear()

    def test_setup_idempotent(self):
        config = LoggingConfig(level="INFO")
        config.setup()
        config.setup()  # Second call should be no-op
        logger = logging.getLogger("encrypted_ir")
        # Should still have exactly one handler
        assert len(logger.handlers) == 1
        logger.handlers.clear()

    def test_get_logger_returns_child(self):
        config = LoggingConfig(level="INFO")
        logger = config.get_logger("test_module")
        assert logger.name == "encrypted_ir.test_module"
        # Cleanup
        logging.getLogger("encrypted_ir").handlers.clear()

    def test_custom_handler(self):
        handler = (
            logging.handlers.MemoryHandler(capacity=100)
            if hasattr(logging, "handlers")
            else logging.StreamHandler()
        )
        config = LoggingConfig(handler=handler)
        config.setup()
        logger = logging.getLogger("encrypted_ir")
        assert handler in logger.handlers
        logger.handlers.clear()

    def test_json_output_through_config(self):
        """End-to-end: config → logger → JSON output."""
        import io

        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        config = LoggingConfig(level="DEBUG", handler=handler)
        config.setup()

        logger = config.get_logger("e2e")
        set_correlation_id("e2e-corr-123")
        logger.info("Encryption complete", extra={"doc_id": "doc-456"})

        output = stream.getvalue()
        parsed = json.loads(output.strip())

        assert parsed["level"] == "INFO"
        assert parsed["message"] == "Encryption complete"
        assert parsed["correlation_id"] == "e2e-corr-123"
        assert parsed["doc_id"] == "doc-456"

        # Cleanup
        logging.getLogger("encrypted_ir").handlers.clear()
