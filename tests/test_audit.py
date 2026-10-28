"""Tests for the audit entry schema and the per-tenant HMAC chain (issue #44)."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import uuid
from base64 import b64encode
from collections.abc import Iterator

import pytest
from alembic import command
from sqlalchemy import delete, insert, select, update
from sqlalchemy.engine import Engine

from encrypted_ir import audit, document_service
from encrypted_ir.audit import GENESIS_HASH, AuditEvent, AuditEventType
from encrypted_ir.database import (
    audit_chain_heads_table,
    audit_log_table,
    create_database_engine,
    create_database_schema,
    document_tokens_table,
    documents_table,
)
from encrypted_ir.document_service import DocumentService
from encrypted_ir.logging import bind_correlation_id, reset_correlation_id
from encrypted_ir.migrations import alembic_config
from encrypted_ir.tools import export_audit

MASTER_KEY = bytes(range(32))


def _event(n: int = 0, **overrides) -> AuditEvent:
    values = {
        "event_type": AuditEventType.DOCUMENT_SEARCH,
        "actor": "user-1",
        "success": True,
        "resource": f"doc-{n}",
        "details": {"result_count": n},
        "request_id": f"req-{n}",
    }
    values.update(overrides)
    return AuditEvent(**values)


def _append(engine: Engine, tenant_id: str, count: int, start: int = 0) -> None:
    key = audit.derive_audit_key(MASTER_KEY, tenant_id)
    for n in range(start, start + count):
        with engine.begin() as conn:
            audit.append(conn, tenant_id, _event(n), key)


def _verify(engine: Engine, tenant_id: str) -> audit.ChainVerification:
    with engine.connect() as conn:
        rows, head = audit.load_chain(conn, tenant_id)
    return audit.verify_chain(rows, head, tenant_id, audit.derive_audit_key(MASTER_KEY, tenant_id))


def _row(engine: Engine, tenant_id: str, at_seq: int):
    with engine.connect() as conn:
        return conn.execute(
            select(audit_log_table).where(
                audit_log_table.c.tenant_id == tenant_id, audit_log_table.c.seq == at_seq
            )
        ).one()


def _set_row(engine: Engine, tenant_id: str, at_seq: int, **values) -> None:
    with engine.begin() as conn:
        conn.execute(
            update(audit_log_table)
            .where(audit_log_table.c.tenant_id == tenant_id, audit_log_table.c.seq == at_seq)
            .values(**values)
        )


@pytest.fixture()
def engine(tmp_path) -> Iterator[Engine]:
    engine = create_database_engine(f"sqlite+pysqlite:///{tmp_path / 'audit.db'}")
    create_database_schema(engine)
    yield engine
    engine.dispose()


class TestKeyAndHash:
    def test_audit_key_is_hkdf_sha256_over_the_tenant(self):
        # RFC 5869 with no salt: PRK = HMAC(zeros, IKM); OKM = HMAC(PRK, info || 0x01).
        label, tenant = b"encrypted-ir/audit-chain/v1", b"tenant-a"
        info = len(label).to_bytes(4, "big") + label + len(tenant).to_bytes(4, "big") + tenant
        prk = hmac.new(bytes(32), MASTER_KEY, hashlib.sha256).digest()
        expected = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()

        assert audit.derive_audit_key(MASTER_KEY, "tenant-a") == expected
        assert expected.hex() == (
            "a2843486502701470878f33c14e63d5c8bd5ea522e3c5865010a65bc40478f73"
        )
        assert audit.derive_audit_key(MASTER_KEY, "tenant-b") != expected

    def test_golden_entry_hash(self):
        entry = {
            "schema_version": 1,
            "seq": 1,
            "tenant_id": "tenant-a",
            "timestamp": "2026-10-27T12:00:00.000000+00:00",
            "event_type": "document.encrypt",
            "actor": "user-1",
            "success": True,
            "resource": "doc-1",
            "details": {"indexed_token_count": 3},
            "request_id": "req-1",
        }
        key = audit.derive_audit_key(MASTER_KEY, "tenant-a")

        assert audit.canonical_json(entry) == (
            b'{"actor":"user-1","details":{"indexed_token_count":3},'
            b'"event_type":"document.encrypt","request_id":"req-1","resource":"doc-1",'
            b'"schema_version":1,"seq":1,"success":true,"tenant_id":"tenant-a",'
            b'"timestamp":"2026-10-27T12:00:00.000000+00:00"}'
        )
        assert audit.entry_hash(key, GENESIS_HASH, entry) == (
            "e338e6e9c87a27c31d5cdd6c43d29eaae2377a87f74d0bb192825da55c9ff380"
        )

    def test_canonical_json_rejects_nan(self):
        with pytest.raises(ValueError):
            audit.canonical_json({"value": float("nan")})


class TestAppend:
    def test_rows_link_and_the_head_follows(self, engine):
        _append(engine, "tenant-a", 3)

        rows = [_row(engine, "tenant-a", seq) for seq in (1, 2, 3)]
        assert rows[0].prev_hash == GENESIS_HASH
        assert rows[1].prev_hash == rows[0].entry_hash
        assert rows[2].prev_hash == rows[1].entry_hash
        with engine.connect() as conn:
            head = conn.execute(select(audit_chain_heads_table)).one()
        assert (head.tenant_id, head.seq, head.entry_hash) == ("tenant-a", 3, rows[2].entry_hash)

    def test_entry_schema_and_columns(self, engine):
        _append(engine, "tenant-a", 1)
        row = _row(engine, "tenant-a", 1)

        assert set(row.entry_json) == {
            "schema_version",
            "seq",
            "tenant_id",
            "timestamp",
            "event_type",
            "actor",
            "success",
            "resource",
            "details",
            "request_id",
        }
        assert row.entry_json["timestamp"].endswith("+00:00")
        assert (row.schema_version, row.event_type, row.actor, row.success, row.request_id) == (
            1,
            "document.search",
            "user-1",
            True,
            "req-0",
        )

    def test_details_are_redacted(self, engine):
        secret = b64encode(os.urandom(32)).decode()
        event = _event(details={"query": "fraud", "note": f"key={secret}", "raw": b"\x00"})
        with engine.begin() as conn:
            audit.append(conn, "tenant-a", event, b"k" * 32)

        stored = json.dumps(_row(engine, "tenant-a", 1).entry_json)
        assert "fraud" not in stored
        assert secret not in stored
        assert "[REDACTED_BYTES]" in stored

    def test_request_id_defaults_to_the_correlation_id(self, engine):
        for tenant_id, correlation_id in (("tenant-a", "corr-123"), ("tenant-b", None)):
            token = bind_correlation_id(correlation_id)
            try:
                with engine.begin() as conn:
                    audit.append(conn, tenant_id, _event(request_id=None), b"k" * 32)
            finally:
                reset_correlation_id(token)

        assert _row(engine, "tenant-a", 1).request_id == "corr-123"
        assert _row(engine, "tenant-b", 1).request_id == ""

    def test_tenants_have_separate_chains(self, engine):
        _append(engine, "tenant-a", 2)
        _append(engine, "tenant-b", 1)

        assert _verify(engine, "tenant-a").head_seq == 2
        assert _verify(engine, "tenant-b").head_seq == 1
        assert _row(engine, "tenant-b", 1).prev_hash == GENESIS_HASH

    def test_rollback_leaves_no_gap(self, engine):
        _append(engine, "tenant-a", 1)
        with pytest.raises(RuntimeError), engine.begin() as conn:
            audit.append(
                conn, "tenant-a", _event(1), audit.derive_audit_key(MASTER_KEY, "tenant-a")
            )
            raise RuntimeError("operation failed after its audit row")
        _append(engine, "tenant-a", 1, start=2)

        result = _verify(engine, "tenant-a")
        assert result.ok
        assert result.head_seq == 2


class TestVerify:
    @pytest.fixture()
    def chained(self, engine) -> Engine:
        _append(engine, "tenant-a", 5)
        _append(engine, "tenant-b", 3)
        return engine

    def test_intact_chain_verifies(self, chained):
        result = _verify(chained, "tenant-a")
        assert result.ok
        assert (result.entries, result.head_seq) == (5, 5)
        assert result.head_hash == _row(chained, "tenant-a", 5).entry_hash

    def test_empty_chain_verifies(self, chained):
        assert _verify(chained, "nobody") == audit.ChainVerification(True, 0, 0, GENESIS_HASH)

    def test_wrong_key_fails_at_the_first_entry(self, chained):
        with chained.connect() as conn:
            rows, head = audit.load_chain(conn, "tenant-a")
        result = audit.verify_chain(rows, head, "tenant-a", b"x" * 32)
        assert (result.ok, result.first_bad_seq) == (False, 1)

    def test_edited_details(self, chained):
        entry = dict(_row(chained, "tenant-a", 3).entry_json)
        entry["details"] = {"result_count": 0}
        _set_row(chained, "tenant-a", 3, entry_json=entry)

        result = _verify(chained, "tenant-a")
        assert (result.ok, result.first_bad_seq) == (False, 3)
        assert "entry_hash" in result.reason
        assert result.head_seq == 2

    def test_deleted_middle_row(self, chained):
        with chained.begin() as conn:
            conn.execute(
                delete(audit_log_table).where(
                    audit_log_table.c.tenant_id == "tenant-a", audit_log_table.c.seq == 3
                )
            )
        result = _verify(chained, "tenant-a")
        assert (result.ok, result.first_bad_seq) == (False, 3)
        assert "missing or reordered" in result.reason

    def test_renumbered_rows_after_a_delete(self, chained):
        # Deleting seq 3 and renumbering 4 and 5 down keeps seq contiguous, but the links break.
        with chained.begin() as conn:
            conn.execute(
                delete(audit_log_table).where(
                    audit_log_table.c.tenant_id == "tenant-a", audit_log_table.c.seq == 3
                )
            )
        for seq in (4, 5):
            _set_row(chained, "tenant-a", seq, seq=seq - 1)

        result = _verify(chained, "tenant-a")
        assert (result.ok, result.first_bad_seq) == (False, 3)

    def test_row_copied_from_another_tenant(self, chained):
        foreign = _row(chained, "tenant-b", 2)
        _set_row(
            chained,
            "tenant-a",
            2,
            entry_json=foreign.entry_json,
            prev_hash=foreign.prev_hash,
            entry_hash=foreign.entry_hash,
        )
        result = _verify(chained, "tenant-a")
        assert (result.ok, result.first_bad_seq) == (False, 2)

    def test_row_moved_to_another_tenant_with_its_entry_rewritten(self, chained):
        # Re-labelling the entry as tenant-a does not help without tenant-a's audit key.
        foreign = _row(chained, "tenant-b", 3)
        with chained.begin() as conn:
            conn.execute(
                insert(audit_log_table).values(
                    tenant_id="tenant-a",
                    entry_json={**foreign.entry_json, "tenant_id": "tenant-a", "seq": 6},
                    schema_version=1,
                    event_type=foreign.event_type,
                    actor=foreign.actor,
                    request_id=foreign.request_id,
                    success=foreign.success,
                    seq=6,
                    prev_hash=_row(chained, "tenant-a", 5).entry_hash,
                    entry_hash=foreign.entry_hash,
                )
            )
        result = _verify(chained, "tenant-a")
        assert (result.ok, result.first_bad_seq) == (False, 6)

    @pytest.mark.parametrize(
        ("column", "value"),
        [("actor", "someone-else"), ("event_type", "document.delete"), ("success", False)],
    )
    def test_edited_column(self, chained, column, value):
        _set_row(chained, "tenant-a", 4, **{column: value})
        result = _verify(chained, "tenant-a")
        assert (result.ok, result.first_bad_seq) == (False, 4)
        assert "column" in result.reason

    def test_truncated_tail_is_caught_by_the_head(self, chained):
        with chained.begin() as conn:
            conn.execute(
                delete(audit_log_table).where(
                    audit_log_table.c.tenant_id == "tenant-a", audit_log_table.c.seq >= 4
                )
            )
        result = _verify(chained, "tenant-a")
        assert not result.ok
        assert result.head_seq == 3
        assert "truncated" in result.reason

    def test_missing_head(self, chained):
        with chained.begin() as conn:
            conn.execute(
                delete(audit_chain_heads_table).where(
                    audit_chain_heads_table.c.tenant_id == "tenant-a"
                )
            )
        result = _verify(chained, "tenant-a")
        assert not result.ok
        assert "head is missing" in result.reason


def _concurrent_appends(engine: Engine, tenant_id: str, threads: int = 8, each: int = 25) -> None:
    key = audit.derive_audit_key(MASTER_KEY, tenant_id)
    errors: list[BaseException] = []
    start = threading.Barrier(threads)

    def worker(index: int) -> None:
        try:
            start.wait()
            for n in range(each):
                with engine.begin() as conn:
                    audit.append(conn, tenant_id, _event(index * 1000 + n), key)
        except BaseException as exc:  # pragma: no cover - reported below
            errors.append(exc)

    pool = [threading.Thread(target=worker, args=(i,)) for i in range(threads)]
    for thread in pool:
        thread.start()
    for thread in pool:
        thread.join()
    assert errors == []


class TestConcurrency:
    def test_file_sqlite(self, engine):
        _concurrent_appends(engine, "tenant-a")
        result = _verify(engine, "tenant-a")
        assert result.ok, result.reason
        assert result.head_seq == 200

    @pytest.mark.integration
    def test_postgres(self):
        database_url = os.environ.get("POSTGRES_TEST_DATABASE_URL")
        if not database_url:
            pytest.skip("POSTGRES_TEST_DATABASE_URL is not configured")
        # Migrate rather than create_all, which cannot alter tables an older revision made.
        command.upgrade(alembic_config(database_url), "head")
        engine = create_database_engine(database_url)
        tenant_id = f"tenant-{uuid.uuid4()}"
        try:
            _concurrent_appends(engine, tenant_id)
            result = _verify(engine, tenant_id)
        finally:
            engine.dispose()
        assert result.ok, result.reason
        assert result.head_seq == 200


class TestServiceWrites:
    @pytest.fixture()
    def service(self, engine) -> DocumentService:
        return DocumentService(engine, MASTER_KEY)

    def _event_types(self, engine: Engine, tenant_id: str) -> list[str]:
        with engine.connect() as conn:
            rows, _ = audit.load_chain(conn, tenant_id)
        return [row.event_type for row in rows]

    def test_ingest_and_delete_are_chained(self, engine, service):
        service.ingest_document("t", "doc-1", "fraud report", actor="alice", request_id="r1")
        service.delete_document("t", "doc-1", actor="alice", request_id="r2")

        assert [e for e in self._event_types(engine, "t") if e.startswith("document.")] == [
            "document.encrypt",
            "document.delete",
        ]
        assert service.verify_audit_chain("t").ok
        delete_row = _row(engine, "t", _verify(engine, "t").head_seq)
        assert (delete_row.actor, delete_row.request_id) == ("alice", "r2")

    def test_ingest_rolls_back_when_its_audit_fails(self, engine, service, monkeypatch):
        service.ingest_document("t", "warmup", "creates the tenant keys first")

        def broken_append(*args, **kwargs):
            raise RuntimeError("audit store unavailable")

        monkeypatch.setattr(document_service.audit, "append", broken_append)
        with pytest.raises(RuntimeError, match="audit store unavailable"):
            service.ingest_document("t", "doc-1", "fraud report")
        monkeypatch.undo()

        with engine.connect() as conn:
            docs = conn.execute(
                select(documents_table.c.doc_id).where(documents_table.c.tenant_id == "t")
            ).all()
            tokens = conn.execute(
                select(document_tokens_table.c.doc_id).where(
                    document_tokens_table.c.doc_id == "doc-1"
                )
            ).all()
        assert [d.doc_id for d in docs] == ["warmup"]
        assert tokens == []
        assert service.verify_audit_chain("t").ok

    def test_delete_rolls_back_when_its_audit_fails(self, engine, service, monkeypatch):
        service.ingest_document("t", "doc-1", "fraud report")
        monkeypatch.setattr(
            document_service.audit,
            "append",
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("audit store unavailable")),
        )
        with pytest.raises(RuntimeError):
            service.delete_document("t", "doc-1")
        monkeypatch.undo()

        assert service.get_document("t", "doc-1").plaintext == "fraud report"
        assert [m.doc_id for m in service.search_documents("t", "fraud")] == ["doc-1"]

    def test_deleting_a_missing_document_is_not_audited(self, engine, service):
        assert service.delete_document("t", "missing") is False
        assert "document.delete" not in self._event_types(engine, "t")


class TestApi:
    def test_requests_are_chained_with_their_request_ids(self, app, client, auth_headers):
        ingest = client.post(
            "/v1/documents",
            json={"doc_id": "doc-1", "content": "fraud report"},
            headers=auth_headers,
        )
        search = client.post("/v1/documents/search", json={"query": "fraud"}, headers=auth_headers)
        assert ingest.status_code == 200
        assert search.status_code == 200

        tenant = "test-tenant-001"  # the auth_headers tenant
        engine = app.state.database_engine
        with engine.connect() as conn:
            rows, _ = audit.load_chain(conn, tenant)
        by_type = {row.event_type: row for row in rows}
        assert by_type["document.encrypt"].request_id == ingest.headers["x-request-id"]
        assert by_type["document.search"].request_id == search.headers["x-request-id"]
        assert "fraud" not in json.dumps([row.entry_json for row in rows])
        assert app.state.document_service.verify_audit_chain(tenant).ok

    def test_failed_read_audit_fails_the_request(self, app, client, auth_headers, monkeypatch):
        client.post(
            "/v1/documents",
            json={"doc_id": "doc-1", "content": "fraud report"},
            headers=auth_headers,
        )

        def broken(*args, **kwargs):
            raise RuntimeError("audit store unavailable")

        monkeypatch.setattr(app.state.document_service, "record_audit_event", broken)
        search = client.post("/v1/documents/search", json={"query": "fraud"}, headers=auth_headers)
        get = client.get("/v1/documents/doc-1", headers=auth_headers)

        for resp in (search, get):
            assert resp.status_code == 500
            assert resp.json()["error"] == "internal_error"
            assert "doc-1" not in resp.text
            assert "fraud" not in resp.text


def _seed_export_db(tmp_path, monkeypatch) -> str:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'export.db'}"
    for name in ("ENCRYPTED_IR_KMS_PROVIDER", "ENCRYPTED_IR_ENV"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setenv("ENCRYPTED_IR_MASTER_KEY_B64", b64encode(MASTER_KEY).decode())
    engine = create_database_engine(database_url)
    create_database_schema(engine)
    _append(engine, "tenant-a", 4)
    engine.dispose()
    return database_url


class TestExportTool:
    def test_exports_and_verifies(self, tmp_path, monkeypatch, capsys):
        _seed_export_db(tmp_path, monkeypatch)
        output = tmp_path / "audit.jsonl"

        assert export_audit.main(["--tenant", "tenant-a", "--output", str(output)]) == 0

        lines = [json.loads(line) for line in output.read_text().splitlines()]
        assert [line["seq"] for line in lines] == [1, 2, 3, 4]
        assert lines[0]["prev_hash"] == GENESIS_HASH
        assert lines[1]["prev_hash"] == lines[0]["entry_hash"]
        summary = json.loads(capsys.readouterr().err)
        assert summary["verified"] is True
        assert (summary["head_seq"], summary["head_hash"]) == (4, lines[-1]["entry_hash"])
        assert summary["unchained_legacy_rows"] == 0

    def test_since_filters_output_but_verifies_everything(self, tmp_path, monkeypatch, capsys):
        database_url = _seed_export_db(tmp_path, monkeypatch)
        engine = create_database_engine(database_url)
        entry = dict(_row(engine, "tenant-a", 1).entry_json)
        entry["actor"] = "tampered"
        _set_row(engine, "tenant-a", 1, entry_json=entry)
        engine.dispose()

        assert (
            export_audit.main(["--tenant", "tenant-a", "--since", "2999-01-01T00:00:00+00:00"]) == 2
        )
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "chain broken at seq 1" in captured.err

    def test_tampered_row_exits_2(self, tmp_path, monkeypatch, capsys):
        database_url = _seed_export_db(tmp_path, monkeypatch)
        engine = create_database_engine(database_url)
        _set_row(engine, "tenant-a", 2, actor="someone-else")
        engine.dispose()

        assert export_audit.main(["--tenant", "tenant-a"]) == 2
        assert "chain broken at seq 2" in capsys.readouterr().err

    def test_check_head_catches_a_rewritten_head(self, tmp_path, monkeypatch, capsys):
        database_url = _seed_export_db(tmp_path, monkeypatch)
        assert export_audit.main(["--tenant", "tenant-a"]) == 0
        exported = json.loads(capsys.readouterr().err)
        head = f"{exported['head_seq']}:{exported['head_hash']}"

        # Drop the last entry and rewrite the head row to match: the chain verifies by itself.
        engine = create_database_engine(database_url)
        third = _row(engine, "tenant-a", 3)
        with engine.begin() as conn:
            conn.execute(
                delete(audit_log_table).where(
                    audit_log_table.c.tenant_id == "tenant-a", audit_log_table.c.seq == 4
                )
            )
            conn.execute(
                update(audit_chain_heads_table)
                .where(audit_chain_heads_table.c.tenant_id == "tenant-a")
                .values(seq=3, entry_hash=third.entry_hash)
            )
        engine.dispose()

        assert export_audit.main(["--tenant", "tenant-a"]) == 0
        capsys.readouterr()
        assert export_audit.main(["--tenant", "tenant-a", "--check-head", head]) == 2
        assert "no longer contains head" in capsys.readouterr().err

    def test_check_head_passes_on_a_longer_chain(self, tmp_path, monkeypatch, capsys):
        database_url = _seed_export_db(tmp_path, monkeypatch)
        engine = create_database_engine(database_url)
        head = f"2:{_row(engine, 'tenant-a', 2).entry_hash}"
        engine.dispose()

        assert export_audit.main(["--tenant", "tenant-a", "--check-head", head]) == 0

    def test_counts_legacy_rows(self, tmp_path, monkeypatch, capsys):
        database_url = _seed_export_db(tmp_path, monkeypatch)
        engine = create_database_engine(database_url)
        with engine.begin() as conn:
            conn.execute(
                insert(audit_log_table).values(
                    tenant_id="tenant-a", entry_json={"operation": "create"}
                )
            )
        engine.dispose()

        assert export_audit.main(["--tenant", "tenant-a"]) == 0
        assert json.loads(capsys.readouterr().err)["unchained_legacy_rows"] == 1

    def test_requires_a_configured_master_key(self, tmp_path, monkeypatch, capsys):
        _seed_export_db(tmp_path, monkeypatch)
        monkeypatch.delenv("ENCRYPTED_IR_MASTER_KEY_B64")

        assert export_audit.main(["--tenant", "tenant-a"]) == 1
        assert "No master key is configured" in capsys.readouterr().err

    @pytest.mark.parametrize(
        "argv",
        [
            ["--tenant", "t", "--check-head", "4"],
            ["--tenant", "t", "--check-head", "0:" + "a" * 64],
            ["--tenant", "t", "--check-head", "4:" + "g" * 64],
            ["--tenant", "t", "--since", "yesterday"],
            ["--tenant", "t", "--since", "2026-10-01T00:00:00"],
        ],
    )
    def test_rejects_bad_arguments(self, argv):
        with pytest.raises(SystemExit) as exc:
            export_audit.main(argv)
        assert exc.value.code == 2
