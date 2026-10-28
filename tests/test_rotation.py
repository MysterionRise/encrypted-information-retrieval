"""Tests for tenant key rotation with document re-encryption (issue #42)."""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from base64 import b64encode
from datetime import datetime

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import insert, select, text, update

from encrypted_ir import audit, document_service, rotation
from encrypted_ir.database import (
    create_database_engine,
    create_database_schema,
    document_tokens_table,
    documents_table,
    key_rotations_table,
    key_store_table,
)
from encrypted_ir.document_service import (
    DocumentService,
    require_writable_keys,
    seal_document,
)
from encrypted_ir.key_manager import KeyLifecycleState, KeyManager, KeyMetadata
from encrypted_ir.rotation import (
    NoRotationInProgressError,
    RotationInProgressError,
    rotate_tenant_keys,
)
from encrypted_ir.searchable import SearchableEncryption
from encrypted_ir.storage_backend import DatabaseStorageBackend
from encrypted_ir.tools import rotate_tenant_keys as rotate_tool

TENANT = "tenant-a"
ENCRYPTION = DocumentService.DOC_ENCRYPTION_KEY_TYPE
SEARCH = DocumentService.DOC_SEARCH_KEY_TYPE
QUERIES = ["fraud", "fraud risk", "treasury liquidity", "quarterly review", "nothing-matches"]
CORPUS = {
    f"doc-{i:02d}": text_
    for i, text_ in enumerate(
        [
            "Quarterly fraud review for treasury",
            "Liquidity risk memo for the treasury desk",
            "Fraud risk escalation from card operations",
            "Quarterly liquidity review and stress test",
            "Vendor onboarding checklist",
            "Fraud ring analysis with risk scores",
            "Treasury liquidity forecast for the quarter",
        ]
    )
}


@pytest.fixture()
def engine(tmp_path):
    engine = create_database_engine(f"sqlite+pysqlite:///{tmp_path / 'rotation.db'}")
    create_database_schema(engine)
    yield engine
    engine.dispose()


@pytest.fixture()
def master_key():
    return os.urandom(32)


@pytest.fixture()
def service(engine, master_key):
    return DocumentService(engine, master_key)


def _ingest_corpus(service, tenant=TENANT, corpus=CORPUS):
    for doc_id, content in corpus.items():
        service.ingest_document(tenant, doc_id, content, metadata={"doc": doc_id})


def _snapshot(service, tenant=TENANT, doc_ids=CORPUS):
    """Everything a caller can observe: OR and AND results with scores, and every decrypt."""
    searches = {
        (query, operator): [
            (c.doc_id, c.score, c.metadata)
            for c in service.search_documents(tenant, query, operator, limit=50)
        ]
        for query in QUERIES
        for operator in ("OR", "AND")
    }
    documents = {}
    for doc_id in doc_ids:
        record = service.get_document(tenant, doc_id)
        documents[doc_id] = (record.plaintext, record.metadata)
    return searches, documents


def _doc_keys(engine, tenant=TENANT):
    with engine.connect() as conn:
        rows = conn.execute(
            select(
                documents_table.c.doc_id,
                documents_table.c.encryption_key_id,
                documents_table.c.search_key_id,
            ).where(documents_table.c.tenant_id == tenant)
        ).all()
    return {row.doc_id: (row.encryption_key_id, row.search_key_id) for row in rows}


def _key_states(engine, master_key, tenant=TENANT):
    manager = KeyManager(master_key, DatabaseStorageBackend(engine, tenant), tenant_id=tenant)
    return {
        key_id: manager.get_metadata(key_id).lifecycle_state
        for key_id in manager.list_keys(active_only=False)
    }


def _rotation_row(engine, tenant=TENANT):
    with engine.connect() as conn:
        return conn.execute(
            select(key_rotations_table).where(key_rotations_table.c.tenant_id == tenant)
        ).one_or_none()


class TestRotation:
    def test_reencrypts_retokenizes_and_retires(self, engine, master_key, service):
        _ingest_corpus(service)
        old_keys = set(_doc_keys(engine).values())
        before = _snapshot(service)

        report = rotate_tenant_keys(engine, master_key, TENANT, batch_size=3)

        assert report.complete
        assert (report.documents_reencrypted, report.documents_retokenized) == (7, 7)
        assert report.batches >= 3
        assert report.failed_documents == report.unverified_documents == 0
        assert _snapshot(service) == before
        targets = (report.target_encryption_key_id, report.target_search_key_id)
        assert set(_doc_keys(engine).values()) == {targets}
        [(old_encryption, old_search)] = old_keys
        assert report.retired_keys == [old_encryption]
        assert report.destroyed_keys == [old_search]
        states = _key_states(engine, master_key)
        assert states[old_encryption] == KeyLifecycleState.RETIRED
        assert states[old_search] == KeyLifecycleState.DESTROYED
        assert states[targets[0]] == states[targets[1]] == KeyLifecycleState.ACTIVE
        assert _rotation_row(engine) is None

    def test_old_keys_end_up_retired_and_destroyed(self, engine, master_key, service):
        _ingest_corpus(service)
        [(old_encryption, old_search)] = set(_doc_keys(engine).values())
        rotate_tenant_keys(engine, master_key, TENANT)

        backend = DatabaseStorageBackend(engine, TENANT)
        assert backend.load_key(old_search)[0] == b""  # crypto-shredded
        fresh = KeyManager(master_key, backend, tenant_id=TENANT)
        assert fresh.get_key_for_decryption(old_encryption)  # retired keys still decrypt
        with pytest.raises(ValueError, match="destroyed"):
            fresh.get_key_for_decryption(old_search)
        with pytest.raises(ValueError, match="destroyed"):
            fresh.get_key(old_search)

    def test_new_rows_store_their_keyword_list(self, engine, master_key, service):
        service.ingest_document(TENANT, "doc", "Fraud review", keywords=["AI,", "Model"])
        manager = service._key_manager(TENANT)
        with engine.connect() as conn:
            row = conn.execute(select(documents_table)).one()

        opened = document_service.open_document(manager, TENANT, row, keywords=True)
        assert opened.keywords == ["ai", "model"]

    def test_audit_chain_records_the_rotation(self, engine, master_key, service):
        _ingest_corpus(service)
        report = rotate_tenant_keys(engine, master_key, TENANT, batch_size=4)

        assert service.verify_audit_chain(TENANT).ok
        with engine.connect() as conn:
            rows, _ = audit.load_chain(conn, TENANT)
        events = [row.event_type for row in rows if row.actor == "key-rotation"]
        assert events == ["document.reencrypt", "document.reencrypt", "key.retire", "key.destroy"]
        batch = next(row for row in rows if row.event_type == "document.reencrypt")
        assert batch.entry_json["details"]["run_id"] == report.run_id
        assert "fraud" not in json.dumps([row.entry_json for row in rows])

    def test_rotating_twice(self, engine, master_key, service):
        _ingest_corpus(service)
        before = _snapshot(service)
        first = rotate_tenant_keys(engine, master_key, TENANT)
        second = rotate_tenant_keys(engine, master_key, TENANT)

        assert second.complete
        assert second.retired_keys == [first.target_encryption_key_id]
        assert second.destroyed_keys == [first.target_search_key_id]
        manager = KeyManager(master_key, DatabaseStorageBackend(engine, TENANT), tenant_id=TENANT)
        assert manager.get_metadata(second.target_encryption_key_id).version == 3
        assert _snapshot(service) == before

    def test_empty_tenant(self, engine, master_key):
        report = rotate_tenant_keys(engine, master_key, "nobody")
        assert report.complete
        assert report.documents_reencrypted == 0
        assert report.retired_keys == report.destroyed_keys == []

    def test_documents_ingested_after_the_start_use_the_new_keys(self, engine, master_key, service):
        _ingest_corpus(service)
        report = rotate_tenant_keys(engine, master_key, TENANT, max_batches=0)
        assert report.stopped_early and not report.complete

        result = service.ingest_document(TENANT, "late", "Late fraud memo")

        assert result["key_id"] == report.target_encryption_key_id
        assert _doc_keys(engine)["late"] == (
            report.target_encryption_key_id,
            report.target_search_key_id,
        )


class TestInterruption:
    def test_failed_batch_rolls_back_and_resume_finishes(
        self, engine, master_key, service, monkeypatch
    ):
        _ingest_corpus(service)
        before = _snapshot(service)
        original = rotation._Rotation._replace_tokens
        calls = {"n": 0}

        def crash_on_fifth(self, conn, doc_id, tokens):
            calls["n"] += 1
            if calls["n"] == 5:  # second document of the second batch of three
                raise RuntimeError("simulated crash")
            original(self, conn, doc_id, tokens)

        monkeypatch.setattr(rotation._Rotation, "_replace_tokens", crash_on_fifth)
        with pytest.raises(RuntimeError, match="simulated crash"):
            rotate_tenant_keys(engine, master_key, TENANT, batch_size=3)
        monkeypatch.undo()

        # The first batch committed; the second rolled back completely.
        row = _rotation_row(engine)
        targets = (row.target_encryption_key_id, row.target_search_key_id)
        moved = sorted(d for d, keys in _doc_keys(engine).items() if keys == targets)
        assert moved == ["doc-00", "doc-01", "doc-02"]
        assert _snapshot(service) == before

        with pytest.raises(RotationInProgressError):
            rotate_tenant_keys(engine, master_key, TENANT)
        report = rotate_tenant_keys(engine, master_key, TENANT, resume=True)

        assert report.complete and report.resumed
        assert report.documents_reencrypted == 4
        assert set(_doc_keys(engine).values()) == {targets}
        assert _snapshot(service) == before

    def test_max_batches_then_resume(self, engine, master_key, service):
        _ingest_corpus(service)
        before = _snapshot(service)

        first = rotate_tenant_keys(engine, master_key, TENANT, batch_size=2, max_batches=2)

        assert first.stopped_early and not first.complete
        assert first.documents_reencrypted == 4
        assert first.retired_keys == first.destroyed_keys == []
        assert _snapshot(service) == before  # searches span both keys mid-rotation

        second = rotate_tenant_keys(engine, master_key, TENANT, batch_size=2, resume=True)

        assert second.complete
        assert second.run_id == first.run_id
        assert second.documents_reencrypted == 3
        assert _snapshot(service) == before

    def test_crash_after_claiming_before_new_keys_resumes(self, engine, master_key, service):
        _ingest_corpus(service)
        with engine.begin() as conn:
            conn.execute(
                insert(key_rotations_table).values(
                    tenant_id=TENANT,
                    run_id="crashed",
                    target_encryption_key_id="",
                    target_search_key_id="",
                )
            )

        report = rotate_tenant_keys(engine, master_key, TENANT, resume=True)

        assert report.complete and report.run_id == "crashed"
        assert report.target_encryption_key_id and report.target_search_key_id


class TestMutex:
    def test_second_start_is_refused(self, engine, master_key, service):
        _ingest_corpus(service)
        rotate_tenant_keys(engine, master_key, TENANT, max_batches=0)

        with pytest.raises(RotationInProgressError, match="resume"):
            rotate_tenant_keys(engine, master_key, TENANT)

    def test_resume_without_a_rotation(self, engine, master_key):
        with pytest.raises(NoRotationInProgressError):
            rotate_tenant_keys(engine, master_key, TENANT, resume=True)

    def test_racing_start_conflicts_on_the_primary_key(self, engine, master_key, monkeypatch):
        # Both starts saw no rotation; the second insert hits the primary key.
        real_start = rotation._start

        def start_after_a_rival(engine_, manager, tenant_id, resume):
            with engine_.begin() as conn:
                conn.execute(
                    insert(key_rotations_table).values(
                        tenant_id=tenant_id,
                        run_id="rival",
                        target_encryption_key_id="",
                        target_search_key_id="",
                    )
                )
            monkeypatch.setattr(rotation, "select", lambda *a: _NoRow(*a))
            return real_start(engine_, manager, tenant_id, resume)

        monkeypatch.setattr(rotation, "_start", start_after_a_rival)
        with pytest.raises(RotationInProgressError):
            rotate_tenant_keys(engine, master_key, TENANT)
        assert _rotation_row(engine).run_id == "rival"

    def test_other_tenants_are_independent(self, engine, master_key, service):
        _ingest_corpus(service)
        _ingest_corpus(service, tenant="tenant-b")
        rotate_tenant_keys(engine, master_key, TENANT, max_batches=0)

        assert rotate_tenant_keys(engine, master_key, "tenant-b").complete


class _NoRow:
    """A select() whose result is always empty, standing in for a read before a rival commit."""

    def __init__(self, *args):
        self._statement = select(*args)

    def where(self, *args):
        return self._statement.where(text("1 = 0"))


class TestLegacyRows:
    def _write_pre_40_document(self, engine, master_key, doc_id, content):
        """A document and keys exactly as the code before issue #40 wrote them."""
        encryption_key, search_key = os.urandom(32), os.urandom(32)
        key_ids = (f"document_encryption_{doc_id}", f"document_search_{doc_id}")  # pre-#40 IDs
        rows = []
        for key_id, key_type, key in zip(
            key_ids, (ENCRYPTION, SEARCH), (encryption_key, search_key)
        ):
            nonce = os.urandom(12)
            metadata = KeyMetadata(key_id=key_id, key_type=key_type, created_at=datetime.now())
            rows.append(
                {
                    "tenant_id": TENANT,
                    "key_id": key_id,
                    "encrypted_key": nonce + AESGCM(master_key).encrypt(nonce, key, None),
                    "metadata_json": metadata.to_dict(),
                }
            )
        blob, tokens = SearchableEncryption(encryption_key, search_key).encrypt_document(content)
        with engine.begin() as conn:
            conn.execute(insert(key_store_table), rows)
            conn.execute(
                insert(documents_table).values(
                    tenant_id=TENANT,
                    doc_id=doc_id,
                    encrypted_document=blob,
                    algorithm="aes-gcm",
                    encryption_key_id=key_ids[0],
                    search_key_id=key_ids[1],
                    metadata_json={"source": "legacy"},
                    token_count=len(tokens),
                )
            )
            conn.execute(
                insert(document_tokens_table),
                [{"tenant_id": TENANT, "token": t, "doc_id": doc_id} for t in tokens],
            )

    @staticmethod
    def _drop_keyword_list(engine, doc_id):
        """Make a sealed row look like one ingested before the keyword list existed."""
        with engine.begin() as conn:
            conn.execute(
                update(documents_table)
                .where(documents_table.c.doc_id == doc_id)
                .values(encrypted_keywords=None)
            )

    def test_content_derived_rows_are_retokenized(self, engine, master_key, service):
        self._write_pre_40_document(engine, master_key, "legacy", "legacy fraud memo")
        service.ingest_document(TENANT, "pre-42", "Quarterly fraud review")
        self._drop_keyword_list(engine, "pre-42")
        before = _snapshot(service, doc_ids=["legacy", "pre-42"])

        report = rotate_tenant_keys(engine, master_key, TENANT)

        assert report.complete
        assert (report.documents_retokenized, report.unverified_documents) == (2, 0)
        assert _snapshot(service, doc_ids=["legacy", "pre-42"]) == before
        with engine.connect() as conn:
            rows = conn.execute(select(documents_table)).all()
        assert {row.algorithm for row in rows} == {DocumentService.ALGORITHM}
        assert all(row.encrypted_keywords is not None for row in rows)
        # The pre-#40 keys were the tenant's active keys, so both documents used them.
        assert report.destroyed_keys == ["document_search_legacy"]
        assert report.retired_keys == ["document_encryption_legacy"]

    def test_explicit_keyword_rows_keep_their_search_key(self, engine, master_key, service):
        service.ingest_document(TENANT, "explicit", "short text", keywords=["AI", "Model"])
        service.ingest_document(TENANT, "derived", "Quarterly fraud review")
        self._drop_keyword_list(engine, "explicit")
        old_search = _doc_keys(engine)["explicit"][1]

        report = rotate_tenant_keys(engine, master_key, TENANT)

        assert report.complete
        assert report.unverified_documents == 1
        assert report.destroyed_keys == []
        assert report.still_referenced == {old_search: 1}
        encryption_key, search_key = _doc_keys(engine)["explicit"]
        assert encryption_key == report.target_encryption_key_id  # content was re-encrypted
        assert search_key == old_search
        assert _key_states(engine, master_key)[old_search] == KeyLifecycleState.ROTATING
        assert [c.doc_id for c in service.search_documents(TENANT, "AI")] == ["explicit"]
        assert service.get_document(TENANT, "explicit").plaintext == "short text"


class TestTampering:
    def test_unreadable_document_blocks_retirement(self, engine, master_key, service):
        _ingest_corpus(service)
        with engine.begin() as conn:
            blob = conn.execute(
                select(documents_table.c.encrypted_document).where(
                    documents_table.c.doc_id == "doc-03"
                )
            ).scalar_one()
            conn.execute(
                update(documents_table)
                .where(documents_table.c.doc_id == "doc-03")
                .values(encrypted_document=blob[:-1] + bytes([blob[-1] ^ 1]))
            )
        old = set(_doc_keys(engine).values())

        report = rotate_tenant_keys(engine, master_key, TENANT, batch_size=2)

        assert not report.complete
        assert (report.failed_documents, report.failed_doc_ids) == (1, ["doc-03"])
        assert report.documents_reencrypted == 6
        assert report.retired_keys == report.destroyed_keys == []
        assert _doc_keys(engine)["doc-03"] in old
        assert _rotation_row(engine) is not None
        states = _key_states(engine, master_key)
        assert all(states[key] == KeyLifecycleState.ROTATING for pair in old for key in pair)


class TestConcurrentWrites:
    def test_ingest_retries_when_its_keys_are_retired_mid_write(
        self, engine, master_key, service, monkeypatch
    ):
        service.ingest_document(TENANT, "first", "fraud memo")
        service.delete_document(TENANT, "first")  # keys exist, no documents reference them
        real_seal = document_service.seal_document
        reports = []

        def rotate_then_seal(*args, **kwargs):
            if not reports:  # the ingest already chose the old keys
                reports.append(rotate_tenant_keys(engine, master_key, TENANT))
            return real_seal(*args, **kwargs)

        monkeypatch.setattr(document_service, "seal_document", rotate_then_seal)
        result = service.ingest_document(TENANT, "racing", "racing fraud memo")

        [report] = reports
        assert report.retired_keys and report.destroyed_keys
        assert result["key_id"] == report.target_encryption_key_id
        assert _doc_keys(engine)["racing"] == (
            report.target_encryption_key_id,
            report.target_search_key_id,
        )
        assert [c.doc_id for c in service.search_documents(TENANT, "racing")] == ["racing"]

    def test_a_document_rewritten_mid_batch_is_not_overwritten(
        self, engine, master_key, service, monkeypatch
    ):
        _ingest_corpus(service)
        real_plan = rotation._Rotation._plan
        rewritten = []

        def plan_then_rewrite(self, row):
            planned = real_plan(self, row)
            if row.doc_id == "doc-02" and not rewritten:
                # Deleted and ingested again after the rotation read it (under the new keys).
                service.delete_document(TENANT, "doc-02")
                service.ingest_document(TENANT, "doc-02", "Rewritten audit memo")
                rewritten.append(True)
            return planned

        monkeypatch.setattr(rotation._Rotation, "_plan", plan_then_rewrite)
        report = rotate_tenant_keys(engine, master_key, TENANT, batch_size=3)

        assert report.complete
        assert service.get_document(TENANT, "doc-02").plaintext == "Rewritten audit memo"
        assert [c.doc_id for c in service.search_documents(TENANT, "rewritten")] == ["doc-02"]
        assert "doc-02" not in {c.doc_id for c in service.search_documents(TENANT, "fraud")}

    def test_writable_key_check(self, engine, master_key, service):
        service.ingest_document(TENANT, "doc", "fraud memo")
        keys = _doc_keys(engine)["doc"]
        with engine.begin() as conn:
            require_writable_keys(conn, TENANT, keys)
            with pytest.raises(document_service.KeysChangedError):
                require_writable_keys(conn, TENANT, (keys[0], "missing-key"))

    def test_search_reruns_when_a_key_appears_mid_query(
        self, engine, master_key, service, monkeypatch
    ):
        _ingest_corpus(service)
        expected = _snapshot(service)[0][("fraud risk", "AND")]
        real_groups = service._query_token_groups
        rotated = []

        def stale_groups(tenant_id, query):
            groups = real_groups(tenant_id, query)
            if not rotated:  # documents move to a new search key after the tokens were made
                rotated.append(rotate_tenant_keys(engine, master_key, TENANT))
            return groups

        monkeypatch.setattr(service, "_query_token_groups", stale_groups)
        results = service.search_documents(TENANT, "fraud risk", "AND", limit=50)

        assert rotated[0].complete
        assert [(c.doc_id, c.score, c.metadata) for c in results] == expected

    def test_concurrent_ingest_converges(self, engine, master_key):
        writer = DocumentService(engine, master_key)
        _ingest_corpus(writer)
        stop = threading.Event()
        written: list[str] = []
        errors: list[BaseException] = []

        def ingest_loop():
            try:
                n = 0
                while not stop.is_set() or n < 5:
                    doc_id = f"live-{n:03d}"
                    writer.ingest_document(TENANT, doc_id, f"live fraud memo {n}")
                    written.append(doc_id)
                    n += 1
            except BaseException as exc:  # pragma: no cover - reported below
                errors.append(exc)

        thread = threading.Thread(target=ingest_loop)
        thread.start()
        try:
            report = rotate_tenant_keys(engine, master_key, TENANT, batch_size=2)
        finally:
            stop.set()
            thread.join()
        assert errors == []
        if not report.complete:
            report = rotate_tenant_keys(engine, master_key, TENANT, resume=True)

        assert report.complete
        reader = DocumentService(engine, master_key)
        found = {c.doc_id for c in reader.search_documents(TENANT, "live", limit=1000)}
        assert found == set(written)
        targets = {(report.target_encryption_key_id, report.target_search_key_id)}
        assert set(_doc_keys(engine).values()) == targets


class TestKeyManagerRotation:
    def test_begin_rotation_is_atomic(self, engine, master_key, monkeypatch):
        backend = DatabaseStorageBackend(engine, TENANT)
        manager = KeyManager(master_key, backend, tenant_id=TENANT)
        old = manager.create_key(SEARCH)

        def fail(*args, **kwargs):
            raise RuntimeError("storage down")

        monkeypatch.setattr(backend, "save_keys", fail)
        with pytest.raises(RuntimeError):
            manager.begin_rotation([SEARCH])

        assert manager.list_keys(active_only=False) == [old]
        assert manager.get_metadata(old).lifecycle_state == KeyLifecycleState.ACTIVE
        assert backend.list_keys() == [old]

    def test_begin_rotation_saves_keys_and_audit_together(self, engine, master_key):
        manager = KeyManager(master_key, DatabaseStorageBackend(engine, TENANT), tenant_id=TENANT)
        old = manager.create_key(SEARCH)

        new = manager.begin_rotation([SEARCH, SEARCH])[SEARCH]

        fresh = KeyManager(master_key, DatabaseStorageBackend(engine, TENANT), tenant_id=TENANT)
        assert fresh.get_metadata(old).lifecycle_state == KeyLifecycleState.ROTATING
        assert fresh.get_metadata(old).successor_key_id == new
        assert fresh.get_metadata(new).predecessor_key_id == old
        with engine.connect() as conn:
            rows, _ = audit.load_chain(conn, TENANT)
        assert [(r.event_type, r.key_id) for r in rows][-2:] == [
            ("key.create", new),
            ("key.rotate", old),
        ]


class TestCli:
    @pytest.fixture()
    def env(self, tmp_path, monkeypatch, master_key):
        database_url = f"sqlite+pysqlite:///{tmp_path / 'cli.db'}"
        for name in ("ENCRYPTED_IR_KMS_PROVIDER", "ENCRYPTED_IR_ENV"):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv("DATABASE_URL", database_url)
        monkeypatch.setenv("ENCRYPTED_IR_MASTER_KEY_B64", b64encode(master_key).decode())
        engine = create_database_engine(database_url)
        create_database_schema(engine)
        _ingest_corpus(DocumentService(engine, master_key))
        yield engine
        engine.dispose()

    def test_complete_run(self, env, capsys):
        assert rotate_tool.main(["--tenant", TENANT, "--batch-size", "3"]) == 0
        report = json.loads(capsys.readouterr().out)
        assert report["complete"] is True
        assert report["documents_reencrypted"] == 7

    def test_stop_and_resume(self, env, capsys):
        assert (
            rotate_tool.main(["--tenant", TENANT, "--batch-size", "2", "--max-batches", "1"]) == 3
        )
        assert "--resume" in capsys.readouterr().err
        assert rotate_tool.main(["--tenant", TENANT]) == 1
        assert "in progress" in capsys.readouterr().err
        assert rotate_tool.main(["--tenant", TENANT, "--resume"]) == 0

    def test_unreadable_document_exits_2(self, env, capsys):
        with env.begin() as conn:
            conn.execute(
                update(documents_table)
                .where(documents_table.c.doc_id == "doc-01")
                .values(encrypted_metadata=b"\x01\x01\x00")
            )
        assert rotate_tool.main(["--tenant", TENANT]) == 2
        assert "no key was retired" in capsys.readouterr().err

    def test_requires_a_master_key(self, env, monkeypatch, capsys):
        monkeypatch.delenv("ENCRYPTED_IR_MASTER_KEY_B64")
        assert rotate_tool.main(["--tenant", TENANT]) == 1
        assert "No master key" in capsys.readouterr().err

    @pytest.mark.parametrize("argv", [["--tenant", "t", "--batch-size", "0"], ["--resume"]])
    def test_rejects_bad_arguments(self, argv):
        with pytest.raises(SystemExit) as exc:
            rotate_tool.main(argv)
        assert exc.value.code == 2


@pytest.mark.integration
class TestPostgres:
    @pytest.fixture()
    def pg_engine(self, require_postgres):
        engine = create_database_engine(require_postgres)
        yield engine
        engine.dispose()

    def test_rotation_on_postgres(self, pg_engine, master_key):
        tenant = f"tenant-{uuid.uuid4()}"
        service = DocumentService(pg_engine, master_key)
        _ingest_corpus(service, tenant=tenant)
        before = _snapshot(service, tenant=tenant)

        report = rotate_tenant_keys(pg_engine, master_key, tenant, batch_size=3)

        assert report.complete
        assert _snapshot(service, tenant=tenant) == before
        assert service.verify_audit_chain(tenant).ok

    def test_a_write_holding_the_key_row_blocks_retirement(self, pg_engine, master_key):
        tenant = f"tenant-{uuid.uuid4()}"
        service = DocumentService(pg_engine, master_key)
        service.ingest_document(tenant, "existing", "fraud memo")
        old_encryption, old_search = _doc_keys(pg_engine, tenant)["existing"]
        rotate_tenant_keys(pg_engine, master_key, tenant, max_batches=0)  # keys now ROTATING

        # A write that chose the old keys before the rotation: its row is inserted and it
        # holds the key rows FOR SHARE, but it has not committed yet.
        manager = service._key_manager(tenant)
        values = seal_document(
            manager.get_key_for_decryption(old_encryption),
            old_encryption,
            tenant,
            "in-flight",
            "in flight fraud memo",
            {},
            ["flight", "fraud", "memo"],
        )
        writer = pg_engine.connect()
        transaction = writer.begin()
        writer.execute(
            insert(documents_table).values(
                tenant_id=tenant,
                doc_id="in-flight",
                search_key_id=old_search,
                metadata_json={},
                token_count=0,
                **values,
            )
        )
        require_writable_keys(writer, tenant, (old_encryption, old_search))

        reports = []
        rotator = threading.Thread(
            target=lambda: reports.append(
                rotate_tenant_keys(pg_engine, master_key, tenant, resume=True)
            )
        )
        rotator.start()
        try:
            assert _wait_for_lock_wait(pg_engine), "retiring the key did not wait for the writer"
            assert rotator.is_alive()
        finally:
            transaction.commit()
            writer.close()
            rotator.join(timeout=60)

        [report] = reports
        assert report.complete
        assert old_encryption in report.retired_keys
        # The old keys were retired only after the in-flight document moved off them: retiring
        # waited for the writer and then counted its row.
        with pg_engine.connect() as conn:
            rows, _ = audit.load_chain(conn, tenant)
        rotation_events = [row.event_type for row in rows if row.actor == "key-rotation"]
        assert rotation_events == [
            "document.reencrypt",
            "document.reencrypt",
            "key.retire",
            "key.destroy",
        ]
        assert _doc_keys(pg_engine, tenant)["in-flight"] == (
            report.target_encryption_key_id,
            report.target_search_key_id,
        )
        assert service.get_document(tenant, "in-flight").plaintext == "in flight fraud memo"
        assert [c.doc_id for c in service.search_documents(tenant, "flight")] == ["in-flight"]


def _wait_for_lock_wait(engine, timeout: float = 20.0) -> bool:
    """Poll until some session of this database waits on a lock."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with engine.connect() as conn:
            waiting = conn.execute(
                text(
                    "SELECT count(*) FROM pg_stat_activity "
                    "WHERE datname = current_database() AND wait_event_type = 'Lock'"
                )
            ).scalar_one()
        if waiting:
            return True
        time.sleep(0.05)
    return False
