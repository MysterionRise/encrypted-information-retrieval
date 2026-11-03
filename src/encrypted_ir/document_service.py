"""Durable encrypted document retrieval service for RAG-style workflows."""

from __future__ import annotations

import json
import threading
import time
from collections import OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Integer, and_, case, delete, func, insert, literal, select
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError

from . import audit, document_crypto
from .audit import AuditEvent, AuditEventType, ChainVerification, derive_audit_key
from .database import document_tokens_table, documents_table
from .errors import DocumentAlreadyExistsError, DocumentIntegrityError, DocumentNotFoundError
from .key_manager import KeyLifecycleState, KeyManager
from .searchable import extract_keywords, normalize_keyword, search_token
from .storage_backend import DatabaseStorageBackend

MAX_QUERY_KEYWORDS = 32


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
    """Persist encrypted documents and deterministic keyword search tokens.

    Content and metadata are sealed with AES-256-GCM under the tenant's document key, bound to
    the tenant, the document ID and the key ID (see :mod:`encrypted_ir.document_crypto`). Rows
    written before that format (``algorithm == "aes-gcm"``) remain readable.

    The service is safe to share between threads. Per-tenant key managers are cached in a
    bounded LRU with a TTL; key reads never write to the database, and keys created by other
    processes are picked up before every ingest and search.
    """

    DOC_ENCRYPTION_KEY_TYPE = "document_encryption"
    DOC_SEARCH_KEY_TYPE = "document_search"
    ALGORITHM = document_crypto.ALGORITHM
    KEY_CACHE_MAX_TENANTS = 1024
    KEY_CACHE_TTL_SECONDS = 300.0

    def __init__(
        self,
        engine: Engine,
        master_key: bytes,
        *,
        key_cache_max_tenants: int = KEY_CACHE_MAX_TENANTS,
        key_cache_ttl_seconds: float = KEY_CACHE_TTL_SECONDS,
    ):
        self._engine = engine
        self._master_key = master_key
        self._key_cache_max_tenants = key_cache_max_tenants
        self._key_cache_ttl_seconds = key_cache_ttl_seconds
        self._key_managers: OrderedDict[str, tuple[float, KeyManager]] = OrderedDict()
        self._key_cache_lock = threading.Lock()

    def cached_tenant_count(self) -> int:
        """Number of tenants whose key managers are cached (for the metrics gauge)."""
        with self._key_cache_lock:
            return len(self._key_managers)

    def _cached_key_manager(self, tenant_id: str) -> KeyManager | None:
        entry = self._key_managers.get(tenant_id)
        if entry is None:
            return None
        loaded_at, manager = entry
        if time.monotonic() - loaded_at >= self._key_cache_ttl_seconds:
            del self._key_managers[tenant_id]
            return None
        self._key_managers.move_to_end(tenant_id)
        return manager

    def _key_manager(self, tenant_id: str) -> KeyManager:
        with self._key_cache_lock:
            cached = self._cached_key_manager(tenant_id)
            if cached is not None:
                return cached

        # Build outside the cache lock so one tenant's database load does not block others.
        manager = KeyManager(
            master_key=self._master_key,
            storage_backend=DatabaseStorageBackend(self._engine, tenant_id),
            tenant_id=tenant_id,
        )
        with self._key_cache_lock:
            cached = self._cached_key_manager(tenant_id)
            if cached is not None:
                return cached
            self._key_managers[tenant_id] = (time.monotonic(), manager)
            while len(self._key_managers) > self._key_cache_max_tenants:
                self._key_managers.popitem(last=False)
        return manager

    @staticmethod
    def _normalize_keywords(keywords: Iterable[str]) -> set[str]:
        normalized = (normalize_keyword(keyword) for keyword in keywords)
        return {keyword for keyword in normalized if keyword}

    @staticmethod
    def _extract_query_keywords(query: str) -> list[str]:
        keywords = sorted(extract_keywords(query, max_keywords=MAX_QUERY_KEYWORDS))
        if keywords:
            return keywords
        # A query made only of short words or stop words is matched as one explicit keyword,
        # for example "AI" against a document ingested with keywords=["AI"].
        fallback = normalize_keyword(query)
        return [fallback] if fallback else []

    @staticmethod
    def _encode_metadata(metadata: dict[str, Any]) -> bytes:
        return json.dumps(metadata, separators=(",", ":"), sort_keys=True).encode("utf-8")

    def _open_row(self, tenant_id: str, row: Any, *, content: bool) -> tuple[dict[str, Any], str]:
        """Return (metadata, plaintext) for a document row; plaintext is "" unless ``content``.

        Raises:
            DocumentIntegrityError: If a ciphertext does not authenticate for this row.
        """
        key = self._key_manager(tenant_id).get_key_for_decryption(row.encryption_key_id)
        if row.algorithm == document_crypto.LEGACY_ALGORITHM:
            plaintext = (
                document_crypto.open_legacy(key, bytes(row.encrypted_document)) if content else b""
            )
            return dict(row.metadata_json or {}), plaintext.decode("utf-8")
        if row.algorithm != document_crypto.ALGORITHM or row.encrypted_metadata is None:
            raise DocumentIntegrityError("Document row has an unknown or incomplete format")

        context = {"key_id": row.encryption_key_id, "tenant_id": tenant_id, "doc_id": row.doc_id}
        metadata_bytes = document_crypto.open_sealed(
            key,
            bytes(row.encrypted_metadata),
            purpose=document_crypto.PURPOSE_METADATA,
            **context,
        )
        plaintext = (
            document_crypto.open_sealed(
                key,
                bytes(row.encrypted_document),
                purpose=document_crypto.PURPOSE_CONTENT,
                **context,
            )
            if content
            else b""
        )
        return json.loads(metadata_bytes), plaintext.decode("utf-8")

    def _audit_key(self, tenant_id: str) -> bytes:
        return derive_audit_key(self._master_key, tenant_id)

    def record_audit_event(
        self,
        tenant_id: str,
        event_type: str,
        actor: str,
        success: bool,
        resource: str = "",
        details: dict[str, Any] | None = None,
        request_id: str | None = None,
    ) -> None:
        """Append an audit event to the tenant's chain in its own transaction.

        Used for events that have no write of their own to share a transaction with (reads,
        rejected requests, failures). ``details`` is redacted before it is stored.
        """
        event = AuditEvent(event_type, actor, success, resource, details or {}, request_id)
        with self._engine.begin() as conn:
            audit.append(conn, tenant_id, event, self._audit_key(tenant_id))

    def verify_audit_chain(self, tenant_id: str) -> ChainVerification:
        """Verify ``tenant_id``'s audit chain from its first entry to the head row."""
        with self._engine.connect() as conn:
            rows, head = audit.load_chain(conn, tenant_id)
        return audit.verify_chain(rows, head, tenant_id, self._audit_key(tenant_id))

    def ingest_document(
        self,
        tenant_id: str,
        doc_id: str,
        content: str,
        metadata: dict[str, Any] | None = None,
        keywords: Iterable[str] | None = None,
        *,
        actor: str = "system",
        request_id: str | None = None,
    ) -> dict[str, Any]:
        """Encrypt, index, and persist a document for a tenant.

        The ``document.encrypt`` audit row is written in the same transaction as the document,
        so the document is stored only if its audit row is.

        Raises:
            DocumentAlreadyExistsError: If the tenant already has a document with this ID,
                including when a concurrent request inserts it first.
        """
        key_manager = self._key_manager(tenant_id)
        encryption_key_id = key_manager.get_or_create_active_key(
            self.DOC_ENCRYPTION_KEY_TYPE, "RAG document encryption"
        )
        search_key_id = key_manager.get_or_create_active_key(
            self.DOC_SEARCH_KEY_TYPE, "RAG document search tokens"
        )
        encryption_key = key_manager.get_key(encryption_key_id)
        search_key = key_manager.get_key(search_key_id)
        document_keywords = (
            extract_keywords(content) if keywords is None else self._normalize_keywords(keywords)
        )
        tokens = {search_token(search_key, keyword) for keyword in document_keywords}
        context = {"key_id": encryption_key_id, "tenant_id": tenant_id, "doc_id": doc_id}
        sealed_content = document_crypto.seal(
            encryption_key,
            content.encode("utf-8"),
            purpose=document_crypto.PURPOSE_CONTENT,
            **context,
        )
        sealed_metadata = document_crypto.seal(
            encryption_key,
            self._encode_metadata(metadata or {}),
            purpose=document_crypto.PURPOSE_METADATA,
            **context,
        )

        with self._engine.begin() as conn:
            try:
                conn.execute(
                    insert(documents_table).values(
                        tenant_id=tenant_id,
                        doc_id=doc_id,
                        encrypted_document=sealed_content,
                        encrypted_metadata=sealed_metadata,
                        algorithm=self.ALGORITHM,
                        encryption_key_id=encryption_key_id,
                        search_key_id=search_key_id,
                        metadata_json={},
                        token_count=len(tokens),
                    )
                )
            except IntegrityError as exc:
                # The primary key (tenant_id, doc_id) is the only constraint a new row can hit.
                raise DocumentAlreadyExistsError(doc_id) from exc
            if tokens:
                conn.execute(
                    insert(document_tokens_table),
                    [
                        {"tenant_id": tenant_id, "token": token, "doc_id": doc_id}
                        for token in sorted(tokens)
                    ],
                )
            audit.append(
                conn,
                tenant_id,
                AuditEvent(
                    AuditEventType.DOCUMENT_ENCRYPT,
                    actor,
                    True,
                    doc_id,
                    {"indexed_token_count": len(tokens)},
                    request_id,
                ),
                self._audit_key(tenant_id),
            )

        return {
            "doc_id": doc_id,
            "tenant_id": tenant_id,
            "algorithm": self.ALGORITHM,
            "key_id": encryption_key_id,
            "indexed_token_count": len(tokens),
        }

    def _query_token_groups(self, tenant_id: str, query: str) -> dict[str, int]:
        """Map each query token to the index of the keyword it encodes.

        A tenant can hold several search keys (after rotation, or when two processes created
        one at the same time), so every keyword has one token per non-destroyed search key.
        """
        keywords = self._extract_query_keywords(query)
        if not keywords:
            return {}
        key_manager = self._key_manager(tenant_id)
        key_manager.refresh()
        groups: dict[str, int] = {}
        for search_key_id in sorted(
            key_manager.list_keys(key_type=self.DOC_SEARCH_KEY_TYPE, active_only=False)
        ):
            metadata = key_manager.get_metadata(search_key_id)
            if metadata.lifecycle_state == KeyLifecycleState.DESTROYED:
                continue
            search_key = key_manager.get_key_for_decryption(search_key_id)
            for index, keyword in enumerate(keywords):
                groups[search_token(search_key, keyword)] = index
        return groups

    def search_documents(
        self,
        tenant_id: str,
        query: str,
        operator: str = "OR",
        limit: int = 10,
    ) -> list[RetrievalCandidate]:
        """Search encrypted document tokens and return ranked document IDs.

        The score is the number of distinct query keywords a document matches. ``AND``
        returns only documents that match every keyword; ``OR`` returns any match.
        """
        groups = self._query_token_groups(tenant_id, query)
        if not groups:
            return []

        keyword_count = len(set(groups.values()))
        keyword_index = case(
            {token: literal(index, Integer) for token, index in groups.items()},
            value=document_tokens_table.c.token,
        )
        matched_keywords = func.count(keyword_index.distinct())
        score_stmt = (
            select(
                document_tokens_table.c.doc_id.label("doc_id"),
                matched_keywords.label("score"),
            )
            .where(
                document_tokens_table.c.tenant_id == tenant_id,
                document_tokens_table.c.token.in_(list(groups)),
            )
            .group_by(document_tokens_table.c.doc_id)
        )
        if operator == "AND":
            score_stmt = score_stmt.having(matched_keywords >= keyword_count)
        scores = score_stmt.subquery()
        stmt = (
            select(
                documents_table.c.doc_id,
                documents_table.c.algorithm,
                documents_table.c.encryption_key_id,
                documents_table.c.encrypted_metadata,
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
            .order_by(scores.c.score.desc(), documents_table.c.doc_id)
            .limit(limit)
        )

        with self._engine.connect() as conn:
            rows = conn.execute(stmt).all()

        return [
            RetrievalCandidate(
                doc_id=row.doc_id,
                metadata=self._open_row(tenant_id, row, content=False)[0],
                score=int(row.score),
            )
            for row in rows
        ]

    def get_document(self, tenant_id: str, doc_id: str) -> DocumentRecord:
        """Decrypt one document by ID for an authorized tenant.

        Raises:
            DocumentNotFoundError: If the tenant has no document with this ID.
            DocumentIntegrityError: If the stored ciphertext does not authenticate for this
                tenant, document and key.
        """
        stmt = select(documents_table).where(
            documents_table.c.tenant_id == tenant_id,
            documents_table.c.doc_id == doc_id,
        )
        with self._engine.connect() as conn:
            row = conn.execute(stmt).first()
        if row is None:
            raise DocumentNotFoundError(doc_id)

        metadata, plaintext = self._open_row(tenant_id, row, content=True)
        return DocumentRecord(
            doc_id=row.doc_id,
            tenant_id=row.tenant_id,
            metadata=metadata,
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
        """Return ranked candidates for a downstream RAG pipeline.

        A candidate deleted between the search and the decrypt is dropped rather than failing
        the whole request.
        """
        candidates = self.search_documents(tenant_id, query, operator="OR", limit=top_k)
        if not include_plaintext:
            return candidates
        retrieved = []
        for candidate in candidates:
            try:
                candidate.plaintext = self.get_document(tenant_id, candidate.doc_id).plaintext
            except DocumentNotFoundError:
                continue
            retrieved.append(candidate)
        return retrieved

    def delete_document(
        self,
        tenant_id: str,
        doc_id: str,
        *,
        actor: str = "system",
        request_id: str | None = None,
    ) -> bool:
        """Delete a document, its tokens and write its audit row in one transaction.

        The document row is deleted first: a concurrent writer of the same document holds its
        row lock, so the token delete that follows sees that writer's tokens and none are left
        behind.

        Returns:
            True if the document existed (and was audited).
        """
        with self._engine.begin() as conn:
            result = conn.execute(
                delete(documents_table).where(
                    documents_table.c.tenant_id == tenant_id,
                    documents_table.c.doc_id == doc_id,
                )
            )
            conn.execute(
                delete(document_tokens_table).where(
                    document_tokens_table.c.tenant_id == tenant_id,
                    document_tokens_table.c.doc_id == doc_id,
                )
            )
            deleted = bool(result.rowcount > 0)
            if deleted:
                audit.append(
                    conn,
                    tenant_id,
                    AuditEvent(AuditEventType.DOCUMENT_DELETE, actor, True, doc_id, {}, request_id),
                    self._audit_key(tenant_id),
                )
        return deleted
