"""Tests for the shared redaction policy used by logs (and, from #44, audit records)."""

from __future__ import annotations

import hashlib

from encrypted_ir.redaction import REDACTED, REDACTED_BYTES, redact, redact_text


class TestRedactText:
    def test_base64_key_is_redacted(self):
        key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
        assert redact_text(f"key {key}") == "key [REDACTED_KEY]"

    def test_mixed_case_base64url_key_is_redacted(self):
        key = "q3T7pX0aZk9LmN2bV8cR4wE6yU1iO5sD7fG3hJ0k"
        assert "[REDACTED_KEY]" in redact_text(key)

    def test_hex_digest_is_kept(self):
        digest = hashlib.sha256(b"audit entry").hexdigest()
        assert redact_text(f"entry_hash={digest}") == f"entry_hash={digest}"

    def test_millisecond_timestamp_is_kept(self):
        assert redact_text("at 1792592429123 ms") == "at 1792592429123 ms"

    def test_luhn_valid_card_is_redacted(self):
        assert redact_text("card 4111 1111 1111 1111") == "card [REDACTED_CARD]"
        assert redact_text("card 4111-1111-1111-1111") == "card [REDACTED_CARD]"

    def test_non_luhn_digits_are_kept(self):
        assert redact_text("order 1234567890123456") == "order 1234567890123456"

    def test_ssn_and_email(self):
        assert redact_text("123-45-6789") == "[REDACTED_SSN]"
        assert redact_text("mail bob@example.org now") == "mail [REDACTED_EMAIL] now"


class TestRedactStructures:
    def test_sensitive_keys_are_dropped_whatever_their_type(self):
        record = {
            "password": "hunter2",
            "credentials": {"user": "svc", "secret": "x"},
            "tokens": ["t1", "t2"],
            "query": "fraud report for alice",
            "content": b"raw",
            "Plaintext": "secret text",
        }
        assert redact(record) == dict.fromkeys(record, REDACTED)

    def test_bytes_are_never_logged(self):
        assert redact({"blob": b"\x00\x01"}) == {"blob": REDACTED_BYTES}
        assert redact([bytearray(b"x")]) == [REDACTED_BYTES]

    def test_nested_values_are_scanned(self):
        record = {"details": {"note": "contact bob@example.org", "count": 3}}
        assert redact(record) == {"details": {"note": "contact [REDACTED_EMAIL]", "count": 3}}

    def test_structural_fields_are_not_scanned(self):
        value = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
        record = {"request_id": value, "prev_hash": value, "route": "/v1/documents/{doc_id}"}
        assert redact(record) == record

    def test_non_string_scalars_pass_through(self):
        assert redact({"status": 401, "ok": True, "latency": 1.5, "none": None}) == {
            "status": 401,
            "ok": True,
            "latency": 1.5,
            "none": None,
        }
