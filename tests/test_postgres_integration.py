"""Optional PostgreSQL integration tests for durable document retrieval."""

from __future__ import annotations

import os
import uuid

import pytest

from encrypted_ir.database import create_database_engine, create_database_schema
from encrypted_ir.document_service import DocumentService


@pytest.mark.integration
def test_document_service_roundtrip_against_postgres():
    database_url = os.environ.get("POSTGRES_TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("POSTGRES_TEST_DATABASE_URL is not configured")

    engine = create_database_engine(database_url)
    create_database_schema(engine)
    service = DocumentService(engine, os.urandom(32))

    tenant_id = f"tenant-{uuid.uuid4()}"
    doc_id = f"doc-{uuid.uuid4()}"

    service.ingest_document(
        tenant_id=tenant_id,
        doc_id=doc_id,
        content="PostgreSQL durable retrieval for regulated RAG demos",
        metadata={"backend": "postgres"},
    )

    matches = service.search_documents(tenant_id, "regulated RAG", operator="AND", limit=5)
    decrypted = service.get_document(tenant_id, doc_id)

    assert [match.doc_id for match in matches] == [doc_id]
    assert decrypted.metadata["backend"] == "postgres"
    assert decrypted.plaintext == "PostgreSQL durable retrieval for regulated RAG demos"
