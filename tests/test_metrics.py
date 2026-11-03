"""Tests for the Prometheus metrics module.

Assertions use the public registry API (``get_sample_value``) and the text parser, never
prometheus_client internals.
"""

from __future__ import annotations

from prometheus_client import CollectorRegistry
from prometheus_client.parser import text_string_to_metric_families

from encrypted_ir.metrics import UNMATCHED_ROUTE, EncryptionMetrics, method_label


def _sample(metrics: EncryptionMetrics, name: str, **labels: str) -> float | None:
    return metrics.registry.get_sample_value(name, labels)


class TestRequestMetrics:
    def test_observe_request_counts_and_times(self):
        metrics = EncryptionMetrics()
        metrics.observe_request("/v1/documents/{doc_id}", "GET", 200, 0.02)
        metrics.observe_request("/v1/documents/{doc_id}", "GET", 200, 0.3)
        metrics.observe_request("/v1/documents/{doc_id}", "GET", 404, 0.01)

        assert (
            _sample(
                metrics,
                "encrypted_ir_http_requests_total",
                route="/v1/documents/{doc_id}",
                method="GET",
                status="200",
            )
            == 2
        )
        assert (
            _sample(
                metrics,
                "encrypted_ir_http_requests_total",
                route="/v1/documents/{doc_id}",
                method="GET",
                status="404",
            )
            == 1
        )
        assert (
            _sample(
                metrics,
                "encrypted_ir_http_request_duration_seconds_count",
                route="/v1/documents/{doc_id}",
                method="GET",
            )
            == 3
        )
        assert (
            _sample(
                metrics,
                "encrypted_ir_http_request_duration_seconds_bucket",
                route="/v1/documents/{doc_id}",
                method="GET",
                le="0.025",
            )
            == 2
        )

    def test_unknown_methods_share_one_label(self):
        metrics = EncryptionMetrics()
        metrics.observe_request(UNMATCHED_ROUTE, "BREW", 405, 0.001)
        metrics.observe_request(UNMATCHED_ROUTE, "PROPFIND", 405, 0.001)

        assert (
            _sample(
                metrics,
                "encrypted_ir_http_requests_total",
                route=UNMATCHED_ROUTE,
                method="OTHER",
                status="405",
            )
            == 2
        )

    def test_method_label(self):
        assert method_label("get") == "GET"
        assert method_label("DELETE") == "DELETE"
        assert method_label("TRACE") == "OTHER"


class TestSecurityMetrics:
    def test_rejections_by_status_and_reason(self):
        metrics = EncryptionMetrics()
        metrics.record_rejection(401, "token_expired")
        metrics.record_rejection(401, "token_expired")
        metrics.record_rejection(429, "rate_limited")

        assert (
            _sample(
                metrics,
                "encrypted_ir_auth_rejections_total",
                status="401",
                reason="token_expired",
            )
            == 2
        )
        assert (
            _sample(
                metrics,
                "encrypted_ir_auth_rejections_total",
                status="429",
                reason="rate_limited",
            )
            == 1
        )

    def test_security_audit_dropped(self):
        metrics = EncryptionMetrics()
        metrics.record_security_audit_dropped("per_source")
        metrics.record_security_audit_dropped("total")
        metrics.record_security_audit_dropped("total")
        assert _sample(metrics, "encrypted_ir_security_audit_dropped_total", limit="total") == 2


class TestKeyCacheGauge:
    def test_gauge_reads_the_callback_at_scrape_time(self):
        metrics = EncryptionMetrics()
        size = [3]
        metrics.track_key_cache(lambda: size[0])
        assert _sample(metrics, "encrypted_ir_key_cache_tenants") == 3
        size[0] = 7
        assert _sample(metrics, "encrypted_ir_key_cache_tenants") == 7


class TestExposition:
    def test_collect_is_parseable_text(self):
        metrics = EncryptionMetrics()
        metrics.observe_request("/health", "GET", 200, 0.001)
        families = {f.name: f for f in text_string_to_metric_families(metrics.collect().decode())}

        assert "encrypted_ir_http_requests" in families
        assert "encrypted_ir_http_request_duration_seconds" in families
        assert "encrypted_ir_auth_rejections" in families
        assert "encrypted_ir_security_audit_dropped" in families
        assert "encrypted_ir_key_cache_tenants" in families

    def test_custom_namespace_and_registry(self):
        registry = CollectorRegistry()
        metrics = EncryptionMetrics(registry=registry, namespace="custom")
        metrics.observe_request("/health", "GET", 200, 0.001)

        assert metrics.registry is registry
        assert (
            registry.get_sample_value(
                "custom_http_requests_total",
                {"route": "/health", "method": "GET", "status": "200"},
            )
            == 1
        )

    def test_registries_are_isolated(self):
        first, second = EncryptionMetrics(), EncryptionMetrics()
        first.observe_request("/health", "GET", 200, 0.001)

        labels = {"route": "/health", "method": "GET", "status": "200"}
        assert first.registry.get_sample_value("encrypted_ir_http_requests_total", labels) == 1
        assert second.registry.get_sample_value("encrypted_ir_http_requests_total", labels) is None
