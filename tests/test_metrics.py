"""Tests for Prometheus metrics collection."""

from __future__ import annotations

import time

import pytest

from encrypted_ir.metrics import EncryptionMetrics


class TestRequestMetrics:
    """Verify request counting and status tracking."""

    def test_record_success(self):
        m = EncryptionMetrics()
        m.record_request("encrypt", "success")
        m.record_request("encrypt", "success")
        m.record_request("decrypt", "success")

        assert m.request_total.labels(operation="encrypt", status="success")._value.get() == 2.0
        assert m.request_total.labels(operation="decrypt", status="success")._value.get() == 1.0

    def test_record_error_increments_both_counters(self):
        m = EncryptionMetrics()
        m.record_error("encrypt", "invalid_key")

        assert (
            m.errors_total.labels(operation="encrypt", error_type="invalid_key")._value.get() == 1.0
        )
        assert m.request_total.labels(operation="encrypt", status="error")._value.get() == 1.0


class TestKeyOperationMetrics:
    """Verify key management operation tracking."""

    def test_key_operations_counted(self):
        m = EncryptionMetrics()
        m.record_key_operation("create")
        m.record_key_operation("create")
        m.record_key_operation("rotate")

        assert m.key_operations_total.labels(operation="create")._value.get() == 2.0
        assert m.key_operations_total.labels(operation="rotate")._value.get() == 1.0


class TestSearchMetrics:
    """Verify search query tracking."""

    def test_search_queries_counted(self):
        m = EncryptionMetrics()
        m.record_search("keyword")
        m.record_search("boolean")
        m.record_search("keyword")

        assert m.search_queries_total.labels(query_type="keyword")._value.get() == 2.0
        assert m.search_queries_total.labels(query_type="boolean")._value.get() == 1.0


class TestCacheMetrics:
    """Verify key cache hit ratio tracking."""

    def test_cache_hit_ratio_updates(self):
        m = EncryptionMetrics()
        m.record_cache_hit()
        m.record_cache_hit()
        m.record_cache_miss()

        # 2 hits / 3 total = 0.6667
        ratio = m.key_cache_hit_ratio._value.get()
        assert abs(ratio - (2 / 3)) < 0.01

    def test_cache_size_gauge(self):
        m = EncryptionMetrics()
        m.set_cache_size(42)
        assert m.key_cache_size._value.get() == 42.0

    def test_initial_ratio_is_zero(self):
        m = EncryptionMetrics()
        assert m.key_cache_hit_ratio._value.get() == 0.0


class TestDurationTracking:
    """Verify the track_duration context manager."""

    def test_successful_duration_recorded(self):
        m = EncryptionMetrics()
        with m.track_duration("encrypt"):
            time.sleep(0.01)

        # Should have recorded one observation
        assert m.request_total.labels(operation="encrypt", status="success")._value.get() == 1.0

    def test_failed_duration_recorded(self):
        m = EncryptionMetrics()
        with pytest.raises(ValueError):
            with m.track_duration("decrypt"):
                raise ValueError("test error")

        assert m.request_total.labels(operation="decrypt", status="error")._value.get() == 1.0


class TestConnectionTracking:
    """Verify active connection gauge."""

    def test_connection_tracking(self):
        m = EncryptionMetrics()
        assert m.active_connections._value.get() == 0.0

        with m.track_connection():
            assert m.active_connections._value.get() == 1.0

        assert m.active_connections._value.get() == 0.0

    def test_multiple_connections(self):
        m = EncryptionMetrics()
        ctx1 = m.track_connection()
        ctx2 = m.track_connection()

        ctx1.__enter__()
        assert m.active_connections._value.get() == 1.0

        ctx2.__enter__()
        assert m.active_connections._value.get() == 2.0

        ctx2.__exit__(None, None, None)
        assert m.active_connections._value.get() == 1.0

        ctx1.__exit__(None, None, None)
        assert m.active_connections._value.get() == 0.0


class TestMetricsExposition:
    """Verify Prometheus exposition format output."""

    def test_collect_returns_bytes(self):
        m = EncryptionMetrics()
        m.record_request("encrypt", "success")
        output = m.collect()
        assert isinstance(output, bytes)
        text = output.decode("utf-8")
        assert "encrypted_ir_requests_total" in text

    def test_all_metrics_present_in_output(self):
        m = EncryptionMetrics()
        # Trigger all metric families
        m.record_request("encrypt", "success")
        m.record_error("decrypt", "invalid_key")
        m.record_key_operation("create")
        m.record_search("keyword")
        m.record_cache_hit()
        m.set_cache_size(10)

        text = m.collect().decode("utf-8")
        assert "encrypted_ir_requests_total" in text
        assert "encrypted_ir_errors_total" in text
        assert "encrypted_ir_key_operations_total" in text
        assert "encrypted_ir_search_queries_total" in text
        assert "encrypted_ir_key_cache_hit_ratio" in text
        assert "encrypted_ir_key_cache_size" in text


class TestIsolatedRegistry:
    """Verify metrics instances don't collide."""

    def test_separate_registries(self):
        m1 = EncryptionMetrics()
        m2 = EncryptionMetrics()

        m1.record_request("encrypt", "success")
        m1.record_request("encrypt", "success")
        m2.record_request("encrypt", "success")

        # Each has its own registry, so counts are independent
        assert m1.request_total.labels(operation="encrypt", status="success")._value.get() == 2.0
        assert m2.request_total.labels(operation="encrypt", status="success")._value.get() == 1.0
