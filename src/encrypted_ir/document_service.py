"""Durable encrypted document retrieval service for RAG-style workflows."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import and_, delete, func, insert, select
from sqlalchemy.engine import Engine

from .database import audit_log_table, document_tokens_table, documents_table
from .key_manager import KeyManager
from .searchable import SearchableEncryption
from .storage_backend import DatabaseStorageBackend


@dataclass
class DocumentRecord:
    """Decrypted document payload returned by the document service."""

    doc_id: str
    tenant_id: str
    metadata: dict[str, Any]
    plaintext: str
    key_id: str


@dataclass
class RetrievalCandidate:
    """Ranked retrieval candidate for downstream RAG systems."""

    doc_id: str
    metadata: dict[str, Any]
    score: int
    plaintext: str | None = None


class DocumentService:
    """Persist encrypted documents and deterministic keyword search tokens."""

    DOC_ENCRYPTION_KEY_TYPE = "document_encryption"
    DOC_SEARCH_KEY_TYPE = "document_search"
    ALGORITHM = "aes-gcm"

    def __init__(self, engine: Engine, master_key: bytes):
        self._engine = engine
        self._master_key = master_key
        self._key_managers: dict[str, KeyManager] = {}

    def _key_manager(self, tenant_id: str) -> KeyManager:
        if tenant_id not in self._key_managers:
            backend = DatabaseStorageBackend(self._engine, tenant_id)
            self._key_managers[tenant_id] = KeyManager(
                master_key=self._master_key,
                storage_backend=backend,
            )
        return self._key_managers[tenant_id]

    @staticmethod
    def _first_or_create_key(
        key_manager: KeyManager,
        key_type: str,
        description: str,
    ) -> str:
        existing = key_manager.list_keys(key_type=key_type, active_only=True)
        if existing:
            return sorted(existing)[0]
        return key_manager.create_key(key_type, key_size=32, description=description)

    def _active_cipher(self, tenant_id: str) -> tuple[SearchableEncryption, str, str]:
        key_manager = self._key_manager(tenant_id)
        encryption_key_id = self._first_or_create_key(
            key_manager,
            self.DOC_ENCRYPTION_KEY_TYPE,
            "RAG document encryption",
        )
        search_key_id = self._first_or_create_key(
            key_manager,
            self.DOC_SEARCH_KEY_TYPE,
            "RAG document search tokens",
        )
        return (
            SearchableEncryption(
                key_manager.get_key(encryption_key_id),
                key_manager.get_key(search_key_id),
            ),
            encryption_key_id,
            search_key_id,
        )

    def _cipher_for_keys(
        self,
        tenant_id: str,
        encryption_key_id: str,
        search_key_id: str,
    ) -> SearchableEncryption:
        key_manager = self._key_manager(tenant_id)
        return SearchableEncryption(
            key_manager.get_key_for_decryption(encryption_key_id),
            key_manager.get_key_for_decryption(search_key_id),
        )

    @staticmethod
    def _extract_query_keywords(query: str) -> set[str]:
        probe = SearchableEncryption()
        keywords = probe._extract_keywords(query)
        if keywords:
            return keywords
        normalized = query.strip().lower()
        return {normalized} if normalized else set()

    def record_audit_event(
        self,
        tenant_id: str,
        event_type: str,
        actor: str,
        success: bool,
        resource: str = "",
        details: dict[str, Any] | None = None,
        request_id: str = "",
    ) -> None:
        """Persist a sanitized API security audit event."""
        sanitized_details = {
            key: ("[REDACTED_BYTES]" if isinstance(value, bytes) else value)
            for key, value in (details or {}).items()
            if key not in {"plaintext", "content", "token", "tokens", "query"}
        }
        record = {
            "event_type": event_type,
            "actor": actor,
            "success": success,
            "resource": resource,
            "details": sanitized_details,
            "request_id": request_id,
        }
        with self._engine.begin() as conn:
            conn.execute(
                insert(audit_log_table).values(
                    tenant_id=tenant_id,
                    key_id=None,
                    entry_json=record,
                )
            )

    def ingest_document(
        self,
        tenant_id: str,
        doc_id: str,
        content: str,
        metadata: dict[str, Any] | None = None,
        keywords: set[str] | None = None,
    ) -> dict[str, Any]:
        """Encrypt, index, and persist a document for a tenant."""
        cipher, encryption_key_id, search_key_id = self._active_cipher(tenant_id)
        encrypted_doc, tokens = cipher.encrypt_document(
            content,
            auto_extract_keywords=keywords is None,
            keywords=keywords,
        )
        metadata = metadata or {}

        with self._engine.begin() as conn:
            exists = conn.execute(
                select(documents_table.c.doc_id).where(
                    documents_table.c.tenant_id == tenant_id,
                    documents_table.c.doc_id == doc_id,
                )
            ).first()
            if exists is not None:
                raise ValueError(f"Document '{doc_id}' already exists for tenant '{tenant_id}'")

            conn.execute(
                insert(documents_table).values(
                    tenant_id=tenant_id,
                    doc_id=doc_id,
                    encrypted_document=encrypted_doc,
                    algorithm=self.ALGORITHM,
                    encryption_key_id=encryption_key_id,
                    search_key_id=search_key_id,
                    metadata_json=metadata,
                    token_count=len(tokens),
                    deleted=False,
                )
            )
            if tokens:
                conn.execute(
                    insert(document_tokens_table),
                    [
                        {"tenant_id": tenant_id, "token": token, "doc_id": doc_id}
                        for token in tokens
                    ],
                )

        return {
            "doc_id": doc_id,
            "tenant_id": tenant_id,
            "algorithm": self.ALGORITHM,
            "key_id": encryption_key_id,
            "indexed_token_count": len(tokens),
        }

    def _query_tokens(self, tenant_id: str, query: str) -> list[str]:
        key_manager = self._key_manager(tenant_id)
        search_key_ids = key_manager.list_keys(
            key_type=self.DOC_SEARCH_KEY_TYPE,
            active_only=False,
        )
        keywords = self._extract_query_keywords(query)
        tokens: list[str] = []
        for search_key_id in search_key_ids:
            search_key = key_manager.get_key_for_decryption(search_key_id)
            cipher = SearchableEncryption(search_key=search_key)
            tokens.extend(cipher.generate_search_query(keyword) for keyword in keywords)
        return tokens

    def search_documents(
        self,
        tenant_id: str,
        query: str,
        operator: str = "OR",
        limit: int = 10,
    ) -> list[RetrievalCandidate]:
        """Search encrypted document tokens and return ranked document IDs."""
        tokens = self._query_tokens(tenant_id, query)
        if not tokens:
            return []

        token_count = len(set(tokens))
        score_stmt = (
            select(
                document_tokens_table.c.doc_id.label("doc_id"),
                func.count(document_tokens_table.c.token).label("score"),
            )
            .where(
                document_tokens_table.c.tenant_id == tenant_id,
                document_tokens_table.c.token.in_(tokens),
            )
            .group_by(document_tokens_table.c.doc_id)
        )
        if operator == "AND":
            score_stmt = score_stmt.having(func.count(document_tokens_table.c.token) >= token_count)
        scores = score_stmt.subquery()
        stmt = (
            select(
                documents_table.c.doc_id,
                documents_table.c.metadata_json,
                scores.c.score,
            )
            .select_from(
                scores.join(
                    documents_table,
                    and_(
                        documents_table.c.tenant_id == tenant_id,
                        documents_table.c.doc_id == scores.c.doc_id,
                    ),
                )
            )
            .where(documents_table.c.deleted.is_(False))
        )
        stmt = stmt.order_by(scores.c.score.desc(), documents_table.c.doc_id)
        stmt = stmt.limit(limit)

        with self._engine.connect() as conn:
            rows = conn.execute(stmt).all()

        return [
            RetrievalCandidate(
                doc_id=row.doc_id,
                metadata=dict(row.metadata_json or {}),
                score=int(row.score),
            )
            for row in rows
        ]

    def get_document(self, tenant_id: str, doc_id: str) -> DocumentRecord:
        """Decrypt one document by ID for an authorized tenant."""
        stmt = select(documents_table).where(
            documents_table.c.tenant_id == tenant_id,
            documents_table.c.doc_id == doc_id,
            documents_table.c.deleted.is_(False),
        )
        with self._engine.connect() as conn:
            row = conn.execute(stmt).first()
        if row is None:
            raise KeyError(f"Document '{doc_id}' not found")

        cipher = self._cipher_for_keys(tenant_id, row.encryption_key_id, row.search_key_id)
        plaintext = cipher.decrypt_document(bytes(row.encrypted_document)).decode("utf-8")
        return DocumentRecord(
            doc_id=row.doc_id,
            tenant_id=row.tenant_id,
            metadata=dict(row.metadata_json or {}),
            plaintext=plaintext,
            key_id=row.encryption_key_id,
        )

    def retrieve_for_rag(
        self,
        tenant_id: str,
        query: str,
        top_k: int = 5,
        include_plaintext: bool = False,
    ) -> list[RetrievalCandidate]:
        """Return ranked candidates for a downstream RAG pipeline."""
        candidates = self.search_documents(tenant_id, query, operator="OR", limit=top_k)
        if include_plaintext:
            for candidate in candidates:
                candidate.plaintext = self.get_document(tenant_id, candidate.doc_id).plaintext
        return candidates

    def delete_document(self, tenant_id: str, doc_id: str) -> bool:
        """Delete a document and its tokens. Used by tests and future admin flows."""
        with self._engine.begin() as conn:
            conn.execute(
                delete(document_tokens_table).where(
                    document_tokens_table.c.tenant_id == tenant_id,
                    document_tokens_table.c.doc_id == doc_id,
                )
            )
            result = conn.execute(
                delete(documents_table).where(
                    documents_table.c.tenant_id == tenant_id,
                    documents_table.c.doc_id == doc_id,
                )
            )
        return bool(result.rowcount > 0)
