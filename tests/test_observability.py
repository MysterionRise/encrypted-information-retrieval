"""Tests for request logging, Prometheus metrics and error handling (issue #43)."""

from __future__ import annotations

import io
import json
import logging
import re

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from encrypted_ir.api.main import create_app
from encrypted_ir.api.routes import admin
from encrypted_ir.database import create_database_engine
from encrypted_ir.logging import StructuredFormatter, current_correlation_id
from encrypted_ir.settings import EncryptedIRSettings
from tests.conftest import bearer, metric

SEARCH = "/v1/documents/search"


@pytest.fixture()
def log_lines(app):
    """Capture every ``encrypted_ir`` log line the app writes, as parsed JSON."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(StructuredFormatter())
    logger = logging.getLogger("encrypted_ir")
    logger.addHandler(handler)

    def _lines() -> list[dict]:
        return [json.loads(line) for line in stream.getvalue().splitlines() if line]

    yield _lines
    logger.removeHandler(handler)


class TestRequestLogging:
    def test_every_line_during_a_request_carries_its_request_id(
        self, app, client, log_lines, monkeypatch
    ):
        def _fail(engine):
            raise RuntimeError("database unreachable")

        # /ready is a sync handler, so its warning is logged from a worker thread.
        monkeypatch.setattr(admin, "database_connects", _fail)
        resp = client.get("/ready", headers={"X-Request-ID": "trace-ready-1"})

        assert resp.status_code == 503
        lines = [line for line in log_lines() if line["correlation_id"] == "trace-ready-1"]
        loggers = {line["logger"] for line in lines}
        assert "encrypted_ir.api.routes.admin" in loggers
        assert "encrypted_ir.api.access" in loggers
        assert all(line["correlation_id"] == "trace-ready-1" for line in log_lines())

    def test_access_line_uses_the_route_template(self, client, auth_headers, log_lines):
        client.get("/v1/documents/private-doc-42", headers=auth_headers)

        [access] = [line for line in log_lines() if line["logger"] == "encrypted_ir.api.access"]
        assert access["route"] == "/v1/documents/{doc_id}"
        assert access["method"] == "GET"
        assert access["status"] == 404
        assert access["tenant_id"] == "test-tenant-001"
        assert "private-doc-42" not in json.dumps(log_lines())

    def test_request_id_does_not_leak_past_the_request(self, client, log_lines):
        before = current_correlation_id()
        client.get("/health", headers={"X-Request-ID": "trace-health"})
        logging.getLogger("encrypted_ir.test").warning("outside any request")

        assert current_correlation_id() == before
        assert log_lines()[-1]["correlation_id"] == before != "trace-health"


class TestUnhandledErrors:
    @pytest.fixture()
    def boom_client(self, app):
        def boom():
            raise RuntimeError("internal detail tenant-b key_7f3a")

        app.add_api_route("/boom", boom, methods=["GET"])
        return TestClient(app, raise_server_exceptions=False)

    def test_500_keeps_request_id_and_is_counted(self, app, boom_client, log_lines):
        resp = boom_client.get("/boom", headers={"X-Request-ID": "trace-500"})

        assert resp.status_code == 500
        assert resp.headers["x-request-id"] == "trace-500"
        assert "x-response-time-ms" in resp.headers
        assert resp.json() == {
            "error": "internal_error",
            "message": "Internal server error",
            "request_id": "trace-500",
            "details": [],
        }
        assert "tenant-b" not in resp.text
        assert (
            metric(
                app,
                "encrypted_ir_http_requests_total",
                route="/boom",
                method="GET",
                status="500",
            )
            == 1
        )
        [error] = [line for line in log_lines() if line["level"] == "ERROR"]
        assert error["correlation_id"] == "trace-500"
        assert "RuntimeError" in error["exception"]


class TestMetricLabels:
    def test_unmatched_paths_share_one_label(self, app, client):
        client.get("/v1/does-not-exist/abc123")
        assert (
            metric(
                app,
                "encrypted_ir_http_requests_total",
                route="unmatched",
                method="GET",
                status="404",
            )
            == 1
        )

    def test_unknown_methods_are_labelled_other(self, app, client):
        resp = client.request("BREW", "/health")
        assert resp.status_code == 405
        assert (
            metric(
                app,
                "encrypted_ir_http_requests_total",
                route="/health",
                method="OTHER",
                status="405",
            )
            == 1
        )

    def test_exposition_never_contains_document_ids(self, client, auth_headers):
        client.post(
            "/v1/documents",
            json={"doc_id": "confidential-doc-7", "content": "quarterly fraud report"},
            headers=auth_headers,
        )
        client.get("/v1/documents/confidential-doc-7", headers=auth_headers)
        client.delete("/v1/documents/confidential-doc-7", headers=auth_headers)

        body = client.get("/metrics").text
        assert "confidential-doc-7" not in body
        assert 'route="/v1/documents/{doc_id}"' in body


class TestMetricsToken:
    TOKEN = "metrics-scrape-token-0123"

    @pytest.fixture()
    def protected(self, settings_factory):
        app = create_app(settings_factory(metrics_token=self.TOKEN))
        return app, TestClient(app)

    def test_token_required(self, protected):
        app, client = protected
        assert client.get("/metrics").status_code == 401
        assert client.get("/metrics", headers=bearer("wrong-token-wrong-token")).status_code == 401
        resp = client.get("/metrics", headers=bearer(self.TOKEN))
        assert resp.status_code == 200
        assert "encrypted_ir_http_requests_total" in resp.text
        assert (
            metric(
                app,
                "encrypted_ir_auth_rejections_total",
                status="401",
                reason="invalid_metrics_token",
            )
            == 2
        )

    def test_short_token_refused(self, settings_factory):
        with pytest.raises(ValueError, match="ENCRYPTED_IR_METRICS_TOKEN"):
            settings_factory(metrics_token="short").validate()

    def test_token_not_in_repr(self, settings_factory):
        assert self.TOKEN not in repr(settings_factory(metrics_token=self.TOKEN))


class TestLoggingSettings:
    def test_log_level_validated(self, settings_factory):
        with pytest.raises(ValueError, match="ENCRYPTED_IR_LOG_LEVEL"):
            settings_factory(log_level="LOUD").validate()

    def test_log_level_applied(self, settings_factory):
        create_app(settings_factory(log_level="WARNING"))
        assert logging.getLogger("encrypted_ir").level == logging.WARNING
        create_app(settings_factory())
        assert logging.getLogger("encrypted_ir").level == logging.INFO

    def test_from_env(self, monkeypatch):
        for name in ("ENCRYPTED_IR_DEV_AUTH_ENABLED", "ENCRYPTED_IR_KMS_PROVIDER"):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv("ENCRYPTED_IR_LOG_LEVEL", "debug")
        monkeypatch.setenv("ENCRYPTED_IR_METRICS_TOKEN", "env-metrics-token-xyz")
        settings = EncryptedIRSettings.from_env()
        assert settings.log_level == "DEBUG"
        assert settings.metrics_token == "env-metrics-token-xyz"

    def test_uvicorn_errors_use_the_json_handler(self, app):
        uvicorn_error = logging.getLogger("uvicorn.error")
        assert uvicorn_error.handlers
        assert isinstance(uvicorn_error.handlers[0].formatter, StructuredFormatter)
        assert uvicorn_error.propagate is False


class TestFormatter:
    def _format(self, **kwargs) -> dict:
        record = logging.LogRecord("encrypted_ir.test", logging.INFO, "t.py", 1, "msg", (), None)
        for key, value in kwargs.items():
            setattr(record, key, value)
        return json.loads(StructuredFormatter().format(record))

    def test_timestamp_is_utc_iso_with_milliseconds(self):
        stamp = self._format()["timestamp"]
        assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", stamp)

    def test_exception_text_is_redacted(self):
        try:
            raise ValueError("lookup failed for alice@example.com")
        except ValueError:
            import sys

            record = logging.LogRecord(
                "encrypted_ir.test", logging.ERROR, "t.py", 1, "failed", (), sys.exc_info()
            )
        parsed = json.loads(StructuredFormatter().format(record))
        assert "alice@example.com" not in parsed["exception"]
        assert "[REDACTED_EMAIL]" in parsed["exception"]


def test_sql_errors_hide_bound_parameters():
    engine = create_database_engine("sqlite+pysqlite:///:memory:")
    with pytest.raises(Exception) as exc_info, engine.connect() as conn:
        conn.execute(text("SELECT :secret FROM table_that_does_not_exist"), {"secret": "s3cr3t"})
    assert "s3cr3t" not in str(exc_info.value)
    assert "hide_parameters" in str(exc_info.value)
