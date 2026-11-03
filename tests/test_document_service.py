"""Service-level tests for DocumentService correctness (issue #39)."""

from __future__ import annotations

import os
from datetime import datetime

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import event, insert, select, update

from encrypted_ir.database import (
    create_database_engine,
    create_database_schema,
    document_tokens_table,
    documents_table,
    key_store_table,
)
from encrypted_ir.document_service import DocumentService
from encrypted_ir.errors import (
    DocumentAlreadyExistsError,
    DocumentIntegrityError,
    DocumentNotFoundError,
    KeyIntegrityError,
)
from encrypted_ir.key_manager import KeyMetadata
from encrypted_ir.searchable import SearchableEncryption, extract_keywords, normalize_keyword
from encrypted_ir.storage_backend import DatabaseStorageBackend

TENANT = "tenant-a"
SEARCH = DocumentService.DOC_SEARCH_KEY_TYPE


@pytest.fixture()
def engine(tmp_path):
    """A file-backed SQLite engine, so several services can share one database."""
    engine = create_database_engine(f"sqlite+pysqlite:///{tmp_path / 'docs.db'}")
    create_database_schema(engine)
    return engine


@pytest.fixture()
def master_key():
    return os.urandom(32)


@pytest.fixture()
def service(engine, master_key):
    return DocumentService(engine, master_key)


def _search_key_id(service: DocumentService) -> str:
    manager = service._key_manager(TENANT)
    return manager.get_or_create_active_key(DocumentService.DOC_SEARCH_KEY_TYPE)


def _count_writes(engine, action):
    statements: list[str] = []

    def _record(conn, cursor, statement, parameters, context, executemany):
        if statement.lstrip().split(" ", 1)[0].upper() in {"INSERT", "UPDATE", "DELETE"}:
            statements.append(statement)

    event.listen(engine, "before_cursor_execute", _record)
    try:
        result = action()
    finally:
        event.remove(engine, "before_cursor_execute", _record)
    return statements, result


class TestKeywordExtraction:
    def test_punctuation_is_stripped_before_filtering(self):
        keywords = extract_keywords('The, and, (or) "fraud" risk... AI, ... "" [x] review.')

        assert keywords == {"fraud", "risk", "review"}

    def test_never_returns_empty_keywords(self):
        assert "" not in extract_keywords('... ,,, "" () [] {} !?')
        assert extract_keywords('... ,,, "" () [] {} !?') == set()

    def test_inner_punctuation_is_kept(self):
        assert extract_keywords("risk/fraud e-mail") == {"risk/fraud", "e-mail"}

    def test_keyword_count_is_capped_in_order_of_appearance(self):
        text = " ".join(f"word{i:05d}" for i in range(50))

        assert extract_keywords(text, max_keywords=10) == {f"word{i:05d}" for i in range(10)}

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [("AI,", "ai"), ("  Fraud. ", "fraud"), ('"(risk)"', "risk"), ("...", "")],
    )
    def test_normalize_keyword(self, raw, expected):
        assert normalize_keyword(raw) == expected

    def test_explicit_keywords_match_queries_with_punctuation(self, service):
        service.ingest_document(TENANT, "doc-ai", "short text", keywords=["AI,", "...", "Model"])

        assert [c.doc_id for c in service.search_documents(TENANT, "AI")] == ["doc-ai"]
        assert [c.doc_id for c in service.search_documents(TENANT, "model.")] == ["doc-ai"]

    def test_explicit_empty_keywords_are_dropped(self, service):
        result = service.ingest_document(TENANT, "doc-empty", "text", keywords=["...", " "])

        assert result["indexed_token_count"] == 0


class TestTenantScopedTokens:
    def test_same_keyword_is_stored_as_different_tokens_per_tenant(self, engine, service):
        service.ingest_document("tenant-a", "doc", "Quarterly fraud review")
        service.ingest_document("tenant-b", "doc", "Quarterly fraud review")

        with engine.connect() as conn:
            rows = conn.execute(
                select(document_tokens_table.c.tenant_id, document_tokens_table.c.token)
            ).all()
        tokens = {
            tenant: {row.token for row in rows if row.tenant_id == tenant}
            for tenant in ("tenant-a", "tenant-b")
        }
        assert tokens["tenant-a"] and tokens["tenant-b"]
        assert tokens["tenant-a"].isdisjoint(tokens["tenant-b"])
        assert [c.doc_id for c in service.search_documents("tenant-b", "fraud")] == ["doc"]


class TestSearchAcrossKeys:
    def test_and_search_matches_documents_under_two_search_keys(self, service):
        service.ingest_document(TENANT, "doc-old-key", "fraud risk report for quarter one")
        old_search_key = _search_key_id(service)
        new_search_key = service._key_manager(TENANT).begin_rotation([SEARCH])[SEARCH]
        service.ingest_document(TENANT, "doc-new-key", "fraud risk report for quarter two")

        with service._engine.connect() as conn:
            rows = dict(
                conn.execute(
                    select(documents_table.c.doc_id, documents_table.c.search_key_id)
                ).all()
            )
        assert rows == {"doc-old-key": old_search_key, "doc-new-key": new_search_key}

        and_ids = {c.doc_id for c in service.search_documents(TENANT, "fraud risk", "AND")}
        or_ids = {c.doc_id for c in service.search_documents(TENANT, "fraud risk", "OR")}

        assert and_ids == {"doc-old-key", "doc-new-key"}
        assert or_ids == {"doc-old-key", "doc-new-key"}

    def test_and_requires_every_keyword(self, service):
        service.ingest_document(TENANT, "both", "fraud and risk")
        service.ingest_document(TENANT, "one", "fraud only")

        assert [c.doc_id for c in service.search_documents(TENANT, "fraud risk", "AND")] == ["both"]

    def test_score_is_number_of_distinct_keywords_matched(self, service):
        service.ingest_document(TENANT, "both", "fraud and risk")
        service.ingest_document(TENANT, "one", "fraud only")
        service._key_manager(TENANT).begin_rotation([SEARCH])

        scores = {c.doc_id: c.score for c in service.search_documents(TENANT, "fraud risk")}

        assert scores == {"both": 2, "one": 1}

    def test_destroyed_search_keys_are_skipped(self, service):
        service.ingest_document(TENANT, "doc", "fraud report")
        manager = service._key_manager(TENANT)
        old_key = _search_key_id(service)
        manager.begin_rotation([SEARCH])
        manager.get_metadata(old_key).lifecycle_state = "destroyed"
        manager._persist_key(old_key)

        assert service.search_documents(TENANT, "fraud") == []


class TestReadPathDoesNotWrite:
    def test_search_get_and_rag_do_not_write(self, engine, master_key, service):
        service.ingest_document(TENANT, "doc", "fraud risk report")

        for reader in (service, DocumentService(engine, master_key)):  # warm and cold caches
            writes, _ = _count_writes(
                engine,
                lambda reader=reader: (
                    reader.search_documents(TENANT, "fraud risk", "AND"),
                    reader.get_document(TENANT, "doc"),
                    reader.retrieve_for_rag(TENANT, "fraud", include_plaintext=True),
                ),
            )
            assert writes == []


class TestSharedDatabase:
    def test_two_service_instances_share_keys(self, engine, master_key):
        service_a = DocumentService(engine, master_key)
        service_b = DocumentService(engine, master_key)

        # B caches a key manager for the tenant before any key exists.
        assert service_b.search_documents(TENANT, "fraud") == []

        service_a.ingest_document(TENANT, "from-a", "fraud report written by a")

        assert [c.doc_id for c in service_b.search_documents(TENANT, "fraud")] == ["from-a"]
        assert service_b.get_document(TENANT, "from-a").plaintext == "fraud report written by a"

        service_b.ingest_document(TENANT, "from-b", "fraud report written by b")
        manager = service_a._key_manager(TENANT)
        manager.refresh()
        assert len(manager.list_keys(DocumentService.DOC_ENCRYPTION_KEY_TYPE)) == 1
        assert len(manager.list_keys(DocumentService.DOC_SEARCH_KEY_TYPE)) == 1

        encryption = DocumentService.DOC_ENCRYPTION_KEY_TYPE
        new_encryption_key = manager.begin_rotation([encryption])[encryption]
        result = service_b.ingest_document(TENANT, "after-rotation", "fraud after rotation")

        assert result["key_id"] == new_encryption_key
        assert {c.doc_id for c in service_a.search_documents(TENANT, "fraud")} == {
            "from-a",
            "from-b",
            "after-rotation",
        }

    def test_key_cache_is_bounded(self, engine, master_key):
        service = DocumentService(engine, master_key, key_cache_max_tenants=3)

        for i in range(10):
            service.search_documents(f"tenant-{i}", "fraud")

        assert len(service._key_managers) == 3
        assert list(service._key_managers) == ["tenant-7", "tenant-8", "tenant-9"]

    def test_key_cache_entries_expire(self, engine, master_key):
        service = DocumentService(engine, master_key, key_cache_ttl_seconds=0)
        first = service._key_manager(TENANT)

        assert service._key_manager(TENANT) is not first


class TestNewestKey:
    def test_ingest_uses_newest_active_key(self, service):
        manager = service._key_manager(TENANT)
        older = manager.create_key(DocumentService.DOC_ENCRYPTION_KEY_TYPE)
        newer = manager.create_key(DocumentService.DOC_ENCRYPTION_KEY_TYPE)
        # Key IDs are random hex, so make "older" sort after "newer" by ID.
        manager.get_metadata(older).created_at = datetime(2020, 1, 1)
        manager.get_metadata(newer).created_at = datetime(2030, 1, 1)
        manager._persist_key(older)
        manager._persist_key(newer)

        assert service.ingest_document(TENANT, "doc", "text")["key_id"] == newer


class TestIngestConflictsAndDeletes:
    def test_duplicate_raises_without_naming_the_tenant(self, service):
        service.ingest_document(TENANT, "dup", "first")

        with pytest.raises(DocumentAlreadyExistsError) as excinfo:
            service.ingest_document(TENANT, "dup", "second")

        assert TENANT not in str(excinfo.value)
        assert service.get_document(TENANT, "dup").plaintext == "first"

    def test_concurrent_duplicate_from_another_instance(self, engine, master_key):
        service_a = DocumentService(engine, master_key)
        service_b = DocumentService(engine, master_key)
        service_a.ingest_document(TENANT, "race", "a wins")

        with pytest.raises(DocumentAlreadyExistsError):
            service_b.ingest_document(TENANT, "race", "b loses")

    def test_same_doc_id_in_two_tenants(self, service):
        service.ingest_document("tenant-a", "shared-id", "tenant a text")
        service.ingest_document("tenant-b", "shared-id", "tenant b text")

        assert service.get_document("tenant-b", "shared-id").plaintext == "tenant b text"

    def test_missing_document_raises_not_found(self, service):
        with pytest.raises(DocumentNotFoundError):
            service.get_document(TENANT, "missing")

    def test_delete_removes_document_and_tokens(self, service):
        service.ingest_document(TENANT, "doc", "fraud report")

        assert service.delete_document(TENANT, "doc") is True
        assert service.delete_document(TENANT, "doc") is False
        with service._engine.connect() as conn:
            tokens = conn.execute(select(document_tokens_table)).all()
        assert tokens == []
        assert service.search_documents(TENANT, "fraud") == []

    def test_delete_is_scoped_to_tenant(self, service):
        service.ingest_document("tenant-a", "doc", "fraud report")

        assert service.delete_document("tenant-b", "doc") is False
        assert service.get_document("tenant-a", "doc").plaintext == "fraud report"

    def test_rag_skips_documents_deleted_mid_request(self, service, monkeypatch):
        service.ingest_document(TENANT, "kept", "fraud report kept")
        service.ingest_document(TENANT, "gone", "fraud report gone")
        original_search = service.search_documents

        def _search_then_delete(*args, **kwargs):
            results = original_search(*args, **kwargs)
            service.delete_document(TENANT, "gone")
            return results

        monkeypatch.setattr(service, "search_documents", _search_then_delete)

        candidates = service.retrieve_for_rag(TENANT, "fraud", include_plaintext=True)

        assert [c.doc_id for c in candidates] == ["kept"]
        assert candidates[0].plaintext == "fraud report kept"


class TestContextBinding:
    """Issue #40: stored ciphertexts and wrapped keys are bound to their row and tenant."""

    @staticmethod
    def _update_document(service, doc_id, tenant=TENANT, **values):
        with service._engine.begin() as conn:
            conn.execute(
                update(documents_table)
                .where(documents_table.c.tenant_id == tenant, documents_table.c.doc_id == doc_id)
                .values(**values)
            )

    @staticmethod
    def _row(service, doc_id, tenant=TENANT):
        with service._engine.connect() as conn:
            return conn.execute(
                select(documents_table).where(
                    documents_table.c.tenant_id == tenant, documents_table.c.doc_id == doc_id
                )
            ).one()

    def test_new_rows_use_the_sealed_format_with_encrypted_metadata(self, service):
        result = service.ingest_document(TENANT, "doc", "secret text", metadata={"tier": "gold"})
        row = self._row(service, "doc")

        assert result["algorithm"] == "aes-256-gcm/v1"
        assert row.algorithm == "aes-256-gcm/v1"
        assert row.metadata_json == {}
        assert b"gold" not in bytes(row.encrypted_metadata)
        assert b"secret text" not in bytes(row.encrypted_document)
        assert service.get_document(TENANT, "doc").metadata == {"tier": "gold"}
        assert service.search_documents(TENANT, "secret")[0].metadata == {"tier": "gold"}

    def test_ciphertext_swapped_between_documents_is_rejected(self, service):
        service.ingest_document(TENANT, "doc-1", "first secret")
        service.ingest_document(TENANT, "doc-2", "second secret")
        second = self._row(service, "doc-2")

        self._update_document(service, "doc-1", encrypted_document=second.encrypted_document)

        with pytest.raises(DocumentIntegrityError):
            service.get_document(TENANT, "doc-1")

    def test_content_and_metadata_cannot_be_swapped(self, service):
        service.ingest_document(TENANT, "doc", "secret text", metadata={"a": 1})
        row = self._row(service, "doc")

        self._update_document(
            service,
            "doc",
            encrypted_document=row.encrypted_metadata,
            encrypted_metadata=row.encrypted_document,
        )

        with pytest.raises(DocumentIntegrityError):
            service.get_document(TENANT, "doc")

    def test_downgrade_to_the_legacy_algorithm_is_rejected(self, service):
        service.ingest_document(TENANT, "doc", "secret text")

        self._update_document(service, "doc", algorithm="aes-gcm")

        with pytest.raises(DocumentIntegrityError):
            service.get_document(TENANT, "doc")

    def test_missing_sealed_metadata_is_rejected(self, service):
        service.ingest_document(TENANT, "doc", "secret text")

        self._update_document(service, "doc", encrypted_metadata=None)

        with pytest.raises(DocumentIntegrityError):
            service.get_document(TENANT, "doc")

    def test_row_pointed_at_another_key_is_rejected(self, service):
        service.ingest_document(TENANT, "doc", "secret text")
        manager = service._key_manager(TENANT)
        other_key = manager.create_key(DocumentService.DOC_ENCRYPTION_KEY_TYPE)

        self._update_document(service, "doc", encryption_key_id=other_key)

        with pytest.raises(DocumentIntegrityError):
            service.get_document(TENANT, "doc")

    def test_tampered_metadata_fails_closed_in_search(self, service):
        service.ingest_document(TENANT, "doc", "fraud report", metadata={"a": 1})
        tampered = bytearray(self._row(service, "doc").encrypted_metadata)
        tampered[-1] ^= 0x01

        self._update_document(service, "doc", encrypted_metadata=bytes(tampered))

        with pytest.raises(DocumentIntegrityError):
            service.search_documents(TENANT, "fraud")

    def test_wrapped_key_copied_to_another_tenant_does_not_unwrap(self, engine, master_key):
        service = DocumentService(engine, master_key)
        service.ingest_document("tenant-a", "doc", "tenant a secret")
        with engine.begin() as conn:
            rows = conn.execute(
                select(key_store_table).where(key_store_table.c.tenant_id == "tenant-a")
            ).all()
            for row in rows:
                conn.execute(
                    insert(key_store_table).values(
                        tenant_id="tenant-b",
                        key_id=row.key_id,
                        encrypted_key=row.encrypted_key,
                        metadata_json=row.metadata_json,
                    )
                )
        copied_key_id = rows[0].key_id
        manager_b = DocumentService(engine, master_key)._key_manager("tenant-b")

        assert manager_b.list_keys(active_only=False) == []
        with pytest.raises(KeyIntegrityError):
            manager_b.get_key_for_decryption(copied_key_id)

    def test_wrapped_key_metadata_is_authenticated(self, engine, master_key):
        service = DocumentService(engine, master_key)
        service.ingest_document(TENANT, "doc", "secret")
        with engine.begin() as conn:
            row = conn.execute(select(key_store_table)).first()
            conn.execute(
                update(key_store_table)
                .where(key_store_table.c.key_id == row.key_id)
                .values(metadata_json={**row.metadata_json, "version": 7})
            )

        with pytest.raises(KeyIntegrityError):
            DocumentService(engine, master_key)._key_manager(TENANT).get_key_for_decryption(
                row.key_id
            )


class TestLegacyRows:
    """Rows and keys written before issue #40 stay readable (the user chose compatibility)."""

    @staticmethod
    def _write_legacy_tenant(engine, master_key, tenant_id):
        """Write keys and one document exactly as the pre-#40 code did."""
        encryption_key, search_key = os.urandom(32), os.urandom(32)
        key_rows = []
        for key_id, key_type, key in (
            (
                "document_encryption_legacy0000001",
                DocumentService.DOC_ENCRYPTION_KEY_TYPE,
                encryption_key,
            ),
            ("document_search_legacy000000001", DocumentService.DOC_SEARCH_KEY_TYPE, search_key),
        ):
            nonce = os.urandom(12)
            wrapped = nonce + AESGCM(master_key).encrypt(nonce, key, None)
            metadata = KeyMetadata(key_id=key_id, key_type=key_type, created_at=datetime.now())
            key_rows.append(
                {
                    "tenant_id": tenant_id,
                    "key_id": key_id,
                    "encrypted_key": wrapped,
                    "metadata_json": metadata.to_dict(),  # no wrap_format: legacy wrapping
                }
            )
        blob, tokens = SearchableEncryption(encryption_key, search_key).encrypt_document(
            "legacy fraud memo"
        )
        with engine.begin() as conn:
            conn.execute(insert(key_store_table), key_rows)
            conn.execute(
                insert(documents_table).values(
                    tenant_id=tenant_id,
                    doc_id="legacy-doc",
                    encrypted_document=blob,
                    algorithm="aes-gcm",
                    encryption_key_id=key_rows[0]["key_id"],
                    search_key_id=key_rows[1]["key_id"],
                    metadata_json={"source": "legacy"},
                    token_count=len(tokens),
                )
            )
            conn.execute(
                insert(document_tokens_table),
                [{"tenant_id": tenant_id, "token": t, "doc_id": "legacy-doc"} for t in tokens],
            )
        return key_rows[0]["key_id"]

    def test_legacy_documents_and_keys_remain_readable(self, engine, master_key):
        self._write_legacy_tenant(engine, master_key, TENANT)
        service = DocumentService(engine, master_key)

        record = service.get_document(TENANT, "legacy-doc")
        matches = service.search_documents(TENANT, "fraud memo", "AND")

        assert record.plaintext == "legacy fraud memo"
        assert record.metadata == {"source": "legacy"}
        assert [(m.doc_id, m.metadata) for m in matches] == [("legacy-doc", {"source": "legacy"})]

    def test_new_documents_coexist_with_legacy_ones(self, engine, master_key):
        legacy_key_id = self._write_legacy_tenant(engine, master_key, TENANT)
        service = DocumentService(engine, master_key)

        result = service.ingest_document(TENANT, "new-doc", "new fraud memo", metadata={"v": 2})

        assert result["key_id"] == legacy_key_id  # the legacy key is still the active key
        assert {m.doc_id for m in service.search_documents(TENANT, "fraud memo", "AND")} == {
            "legacy-doc",
            "new-doc",
        }
        assert service.get_document(TENANT, "new-doc").metadata == {"v": 2}

    def test_legacy_key_is_rewrapped_with_context_on_next_save(self, engine, master_key):
        legacy_key_id = self._write_legacy_tenant(engine, master_key, TENANT)
        manager = DocumentService(engine, master_key)._key_manager(TENANT)

        manager._persist_key(legacy_key_id)

        stored = DatabaseStorageBackend(engine, TENANT).load_key(legacy_key_id)
        assert stored is not None and stored[1]["wrap_format"] == 1
        fresh = DocumentService(engine, master_key)._key_manager(TENANT)
        assert fresh.get_key_for_decryption(legacy_key_id) == manager.get_key(legacy_key_id)
