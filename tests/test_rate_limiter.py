"""Tests for the rate limiter and its wiring into the API (issue #47)."""

from __future__ import annotations

import threading

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from encrypted_ir.api.dependencies.rate_limiter import (
    CLIENT_RATE_LIMIT,
    DEFAULT_LIMITS,
    RateLimitConfig,
    RateLimiter,
    retry_after_header,
)
from encrypted_ir.database import audit_log_table
from encrypted_ir.settings import DEFAULT_RATE_LIMITS, EncryptedIRSettings
from tests.conftest import metric


class _Clock:
    def __init__(self, now: float = 1000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now


def _limiter(max_requests: int, window: float = 60, **kwargs) -> tuple[RateLimiter, _Clock]:
    clock = _Clock()
    limiter = RateLimiter({"op": RateLimitConfig(max_requests, window)}, clock=clock, **kwargs)
    return limiter, clock


class TestGCRA:
    def test_burst_then_steady_rate(self):
        limiter, clock = _limiter(3, 60)

        assert [limiter.try_acquire("t", "op") for _ in range(3)] == [None, None, None]
        assert limiter.try_acquire("t", "op") == pytest.approx(20.0)

        clock.now += 19.9
        assert limiter.try_acquire("t", "op") == pytest.approx(0.1)
        clock.now += 0.1
        assert limiter.try_acquire("t", "op") is None
        assert limiter.try_acquire("t", "op") == pytest.approx(20.0)

    def test_full_refill_after_window(self):
        limiter, clock = _limiter(2, 60)
        limiter.try_acquire("t", "op")
        limiter.try_acquire("t", "op")
        clock.now += 60
        assert [limiter.try_acquire("t", "op") for _ in range(2)] == [None, None]

    def test_keys_are_independent(self):
        limiter, _ = _limiter(1, 60)
        assert limiter.try_acquire("a", "op") is None
        assert limiter.try_acquire("b", "op") is None
        assert limiter.try_acquire("a", "op") is not None

    def test_unknown_operation_is_unlimited(self):
        limiter, _ = _limiter(1, 60)
        assert all(limiter.try_acquire("t", "other") is None for _ in range(10))
        assert limiter.bucket_count() == 0

    @pytest.mark.parametrize("max_requests", [1, 2, 3, 7])
    @pytest.mark.parametrize(
        "start", [9.676010000000002, 0.1, 3.3, 17.000000000000004, 59.99, 1e-9]
    )
    def test_exact_burst_at_any_clock_value(self, max_requests, start):
        # At small clock values (a freshly booted host), (now + interval) - window can round
        # above now; the first max_requests requests must still pass and the next must not.
        clock = _Clock(start)
        limiter = RateLimiter({"op": RateLimitConfig(max_requests, 60)}, clock=clock)

        results = [limiter.try_acquire("k", "op") for _ in range(max_requests + 1)]

        assert results[:max_requests] == [None] * max_requests
        assert results[-1] == pytest.approx(60 / max_requests)

    def test_rounding_regression_value(self):
        start = 9.676010000000002
        assert (start + 60.0) - 60.0 > start  # the value really does round up
        limiter = RateLimiter({"op": RateLimitConfig(1, 60)}, clock=_Clock(start))
        assert limiter.try_acquire("new-key", "op") is None

    def test_retry_after_header_rounds_up(self):
        assert retry_after_header(0.01) == "1"
        assert retry_after_header(19.2) == "20"
        assert retry_after_header(60) == "60"

    def test_concurrent_callers_get_exactly_the_limit(self):
        limiter = RateLimiter({"op": RateLimitConfig(100, 3600)})
        allowed = []
        lock = threading.Lock()

        def worker():
            for _ in range(50):
                if limiter.try_acquire("shared", "op") is None:
                    with lock:
                        allowed.append(1)

        threads = [threading.Thread(target=worker) for _ in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(allowed) == 100


class TestBoundedState:
    def test_bucket_count_is_capped(self):
        limiter, _ = _limiter(5, 60, max_keys=1000)
        for i in range(100_000):
            limiter.try_acquire(f"tenant-{i}", "op")
        assert limiter.bucket_count("op") == 1000

    def test_refilled_buckets_are_dropped(self):
        limiter, clock = _limiter(5, 60)
        for i in range(50):
            limiter.try_acquire(f"tenant-{i}", "op")
        assert limiter.bucket_count() == 50

        clock.now += 60
        limiter.try_acquire("tenant-new", "op")
        assert limiter.bucket_count() == 1

    def test_eviction_never_tightens_a_limit(self):
        limiter, _ = _limiter(1, 60, max_keys=2)
        limiter.try_acquire("a", "op")
        limiter.try_acquire("b", "op")
        limiter.try_acquire("c", "op")  # evicts "a", the least recently used
        assert limiter.try_acquire("a", "op") is None

    def test_reset(self):
        limiter, _ = _limiter(1, 60)
        limiter.try_acquire("a", "op")
        limiter.try_acquire("b", "op")
        limiter.reset("a")
        assert limiter.try_acquire("a", "op") is None
        limiter.reset()
        assert limiter.bucket_count() == 0


class TestSettings:
    def test_defaults_include_the_client_limit(self):
        assert DEFAULT_LIMITS[CLIENT_RATE_LIMIT] == RateLimitConfig(600, 60)
        assert EncryptedIRSettings().effective_rate_limits == dict(DEFAULT_RATE_LIMITS)

    def test_overrides_merge_over_defaults(self):
        settings = EncryptedIRSettings(rate_limits={"document_search": (5, 10)})
        limits = settings.effective_rate_limits
        assert limits["document_search"] == (5, 10)
        assert limits["document_ingest"] == DEFAULT_RATE_LIMITS["document_ingest"]

    @pytest.mark.parametrize(
        ("overrides", "match"),
        [
            ({"document_serch": (1, 60)}, "unknown operation"),
            ({"document_search": (0, 60)}, "positive"),
            ({"client": (10, -1)}, "positive"),
        ],
    )
    def test_invalid_overrides(self, overrides, match):
        with pytest.raises(ValueError, match=match):
            EncryptedIRSettings(rate_limits=overrides).validate()

    def test_invalid_proxies_and_max_keys(self):
        with pytest.raises(ValueError, match="ENCRYPTED_IR_TRUSTED_PROXIES"):
            EncryptedIRSettings(trusted_proxies=("*",)).validate()
        with pytest.raises(ValueError, match="ENCRYPTED_IR_RATE_LIMIT_MAX_KEYS"):
            EncryptedIRSettings(rate_limit_max_keys=0).validate()
        EncryptedIRSettings(trusted_proxies=("10.0.0.1", "10.1.0.0/16", "::1")).validate()

    def test_from_env(self, monkeypatch):
        for name in ("ENCRYPTED_IR_DEV_AUTH_ENABLED", "ENCRYPTED_IR_KMS_PROVIDER"):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv("ENCRYPTED_IR_RATE_LIMITS", '{"client": [30, 10]}')
        monkeypatch.setenv("ENCRYPTED_IR_RATE_LIMIT_MAX_KEYS", "500")
        monkeypatch.setenv("ENCRYPTED_IR_TRUSTED_PROXIES", "10.0.0.1, 10.2.0.0/16")

        settings = EncryptedIRSettings.from_env()

        assert settings.rate_limits == {"client": (30, 10)}
        assert settings.rate_limit_max_keys == 500
        assert settings.trusted_proxies == ("10.0.0.1", "10.2.0.0/16")

    @pytest.mark.parametrize(
        "raw", ["not json", "[1, 2]", '{"client": 5}', '{"client": [1]}', '{"client": [1.5, 60]}']
    )
    def test_from_env_rejects_malformed_json(self, monkeypatch, raw):
        monkeypatch.delenv("ENCRYPTED_IR_DEV_AUTH_ENABLED", raising=False)
        monkeypatch.setenv("ENCRYPTED_IR_RATE_LIMITS", raw)
        with pytest.raises(ValueError, match="ENCRYPTED_IR_RATE_LIMITS"):
            EncryptedIRSettings.from_env()


class TestClientLimit:
    @pytest.fixture()
    def limited(self, app_factory):
        app = app_factory(rate_limits={"client": (2, 60)})
        return app, TestClient(app, client=("198.51.100.7", 40000))

    def test_ready_and_metrics_are_limited_but_health_is_not(self, limited):
        _, client = limited
        assert [client.get("/health").status_code for _ in range(5)] == [200] * 5
        assert client.get("/ready").status_code == 200
        assert client.get("/metrics").status_code == 200
        resp = client.get("/ready")
        assert resp.status_code == 429
        assert resp.headers["retry-after"] == "30"
        assert resp.json()["error"] == "rate_limited"
        assert "x-request-id" in resp.headers

    def test_unauthenticated_requests_are_limited(self, limited):
        _, client = limited
        statuses = [
            client.post("/v1/documents/search", json={"query": "x"}).status_code for _ in range(3)
        ]
        assert statuses == [401, 401, 429]

    def test_client_429_is_counted_and_audited(self, limited):
        app, client = limited
        for _ in range(3):
            client.get("/ready")

        assert (
            metric(
                app,
                "encrypted_ir_auth_rejections_total",
                status="429",
                reason="client_rate_limited",
            )
            == 1
        )
        with app.state.database_engine.connect() as conn:
            rows = conn.execute(
                select(audit_log_table.c.tenant_id, audit_log_table.c.entry_json)
            ).all()
        [(tenant, entry)] = [
            (r.tenant_id, r.entry_json)
            for r in rows
            if r.entry_json.get("event_type") == "rate_limit.exceeded"
        ]
        assert tenant == "_system"
        assert entry["resource"] == "/ready"
        assert entry["details"]["reason"] == "client_rate_limited"

    def test_clients_are_independent(self, app_factory):
        app = app_factory(rate_limits={"client": (1, 60)})
        first = TestClient(app, client=("198.51.100.7", 1))
        second = TestClient(app, client=("198.51.100.8", 1))
        assert first.get("/ready").status_code == 200
        assert second.get("/ready").status_code == 200
        assert first.get("/ready").status_code == 429


class TestTrustedProxies:
    @pytest.fixture()
    def app(self, app_factory):
        return app_factory(rate_limits={"client": (1, 60)}, trusted_proxies=("10.0.0.1",))

    def test_forwarded_address_is_used_from_a_trusted_proxy(self, app):
        proxy = TestClient(app, client=("10.0.0.1", 5000))
        a = {"X-Forwarded-For": "203.0.113.5"}
        b = {"X-Forwarded-For": "203.0.113.6"}

        assert proxy.get("/ready", headers=a).status_code == 200
        assert proxy.get("/ready", headers=b).status_code == 200
        assert proxy.get("/ready", headers=a).status_code == 429

    def test_forwarded_header_is_ignored_from_other_peers(self, app):
        untrusted = TestClient(app, client=("10.9.9.9", 5000))
        assert (
            untrusted.get("/ready", headers={"X-Forwarded-For": "203.0.113.5"}).status_code == 200
        )
        # A spoofed header from the same peer does not buy a fresh allowance.
        assert (
            untrusted.get("/ready", headers={"X-Forwarded-For": "203.0.113.9"}).status_code == 429
        )

    def test_no_proxy_middleware_without_trusted_proxies(self, app_factory):
        app = app_factory(rate_limits={"client": (1, 60)})
        client = TestClient(app, client=("10.0.0.1", 5000))
        assert client.get("/ready", headers={"X-Forwarded-For": "203.0.113.5"}).status_code == 200
        assert client.get("/ready", headers={"X-Forwarded-For": "203.0.113.6"}).status_code == 429


def test_operation_limits_are_per_tenant_and_carry_retry_after(app, client, auth_headers):
    app.state.rate_limiter = RateLimiter({"document_search": RateLimitConfig(1, 60)})
    assert (
        client.post("/v1/documents/search", json={"query": "x"}, headers=auth_headers).status_code
        == 200
    )
    resp = client.post("/v1/documents/search", json={"query": "x"}, headers=auth_headers)
    assert resp.status_code == 429
    assert resp.headers["retry-after"] == "60"
