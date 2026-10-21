"""Service-level tests for DocumentService correctness (issue #39)."""

from __future__ import annotations

import os
from datetime import datetime

import pytest
from sqlalchemy import event, select

from encrypted_ir.database import (
    create_database_engine,
    create_database_schema,
    document_tokens_table,
    documents_table,
)
from encrypted_ir.document_service import DocumentService
from encrypted_ir.errors import DocumentAlreadyExistsError, DocumentNotFoundError
from encrypted_ir.searchable import extract_keywords, normalize_keyword

TENANT = "tenant-a"


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


class TestSearchAcrossKeys:
    def test_and_search_matches_documents_under_two_search_keys(self, service):
        service.ingest_document(TENANT, "doc-old-key", "fraud risk report for quarter one")
        old_search_key = _search_key_id(service)
        new_search_key = service._key_manager(TENANT).rotate_key(old_search_key)
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
        service._key_manager(TENANT).rotate_key(_search_key_id(service))

        scores = {c.doc_id: c.score for c in service.search_documents(TENANT, "fraud risk")}

        assert scores == {"both": 2, "one": 1}

    def test_destroyed_search_keys_are_skipped(self, service):
        service.ingest_document(TENANT, "doc", "fraud report")
        manager = service._key_manager(TENANT)
        old_key = _search_key_id(service)
        manager.rotate_key(old_key)
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

        new_encryption_key = manager.rotate_key(
            manager.get_or_create_active_key(DocumentService.DOC_ENCRYPTION_KEY_TYPE)
        )
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
