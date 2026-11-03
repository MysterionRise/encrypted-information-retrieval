"""Tenant key rotation that re-encrypts stored documents (ADR-018).

:func:`rotate_tenant_keys` rotates a tenant's document-encryption and search keys:

1. **Start.** A row in ``encrypted_ir_key_rotations`` claims the tenant; a second rotation for
   the same tenant conflicts on its primary key and is refused. :meth:`KeyManager.begin_rotation`
   then creates one successor per key type and marks the old keys ROTATING in one transaction.
   From then on every new write uses the successors, while searches and reads still use every
   key that is not destroyed.
2. **Re-encrypt.** Documents still on an old key are processed in batches, in ``doc_id``
   order, one transaction per batch. Each is decrypted, sealed again under the new document
   key (legacy rows are upgraded to the sealed format), and, when its keywords are known, gets
   new search tokens under the new search key. The row is written back only if its ciphertext
   is unchanged since it was read (compare-and-swap), so a concurrent delete or rewrite wins.
   Each batch appends one ``document.reencrypt`` audit event in the same transaction. Passes
   repeat until one makes no progress.
3. **Finish.** Each old key that no document references any more is retired: document keys
   become RETIRED (kept, so backups stay readable) and search keys become DESTROYED, with their
   wrapped bytes cleared. The key row is locked before the count, so a concurrent write that
   still uses the key is either counted or sees the new state and retries.

Keywords come from the sealed keyword list stored at ingest. Rows ingested before that list
existed have no record of their keywords; the tool re-extracts keywords from the content and
uses them only if their tokens under the old search key equal the stored tokens exactly.
Otherwise (typically documents ingested with explicit keywords) the document keeps its old
search key, which stays searchable and is reported, until the document is ingested again.

A run interrupted at any point (crash, ``max_batches``) leaves every document readable and
searchable; ``resume=True`` continues it. If a document fails to decrypt, no key is retired
and the run reports it.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from typing import Any

from sqlalchemy import and_, delete, func, insert, or_, select, update
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import IntegrityError

from . import audit
from .audit import AuditEvent, AuditEventType, derive_audit_key
from .database import (
    document_tokens_table,
    documents_table,
    key_rotations_table,
    key_store_table,
)
from .document_service import DocumentService, open_document, seal_document
from .errors import DocumentIntegrityError, KeyIntegrityError
from .key_manager import KeyLifecycleState, KeyManager
from .searchable import extract_keywords, search_token
from .storage_backend import DatabaseStorageBackend

__all__ = [
    "NoRotationInProgressError",
    "RotationError",
    "RotationInProgressError",
    "RotationReport",
    "rotate_tenant_keys",
]

ACTOR = "key-rotation"
ENCRYPTION_KEY_TYPE = DocumentService.DOC_ENCRYPTION_KEY_TYPE
SEARCH_KEY_TYPE = DocumentService.DOC_SEARCH_KEY_TYPE
MAX_FINISH_ROUNDS = 3
MAX_REPORTED_DOC_IDS = 100

# What a document row fails with when it does not decrypt under its key.
_UNREADABLE = (DocumentIntegrityError, KeyIntegrityError, KeyError, ValueError)


class RotationError(Exception):
    """A rotation cannot start or resume."""


class RotationInProgressError(RotationError):
    """The tenant already has a rotation in progress; resume it instead."""


class NoRotationInProgressError(RotationError):
    """``resume`` was requested but the tenant has no rotation in progress."""


@dataclass
class RotationReport:
    """Outcome of one :func:`rotate_tenant_keys` call."""

    tenant_id: str
    run_id: str
    resumed: bool
    target_encryption_key_id: str
    target_search_key_id: str
    batches: int = 0
    documents_reencrypted: int = 0
    documents_retokenized: int = 0
    failed_documents: int = 0
    failed_doc_ids: list[str] = field(default_factory=list)
    # Documents whose keywords could not be verified: they keep an old search key.
    unverified_documents: int = 0
    retired_keys: list[str] = field(default_factory=list)
    destroyed_keys: list[str] = field(default_factory=list)
    still_referenced: dict[str, int] = field(default_factory=dict)
    stopped_early: bool = False
    complete: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def rotate_tenant_keys(
    engine: Engine,
    master_key: bytes,
    tenant_id: str,
    *,
    batch_size: int = 100,
    resume: bool = False,
    max_batches: int | None = None,
) -> RotationReport:
    """Rotate ``tenant_id``'s document and search keys and re-encrypt its documents.

    Args:
        engine: Database engine, migrated to the current schema.
        master_key: The app master key the API uses.
        tenant_id: Tenant to rotate.
        batch_size: Documents per transaction.
        resume: Continue the tenant's rotation in progress instead of starting one.
        max_batches: Stop after this many batches (the rotation stays in progress).

    Raises:
        RotationInProgressError: ``resume`` is False and a rotation is in progress.
        NoRotationInProgressError: ``resume`` is True and no rotation is in progress.
    """
    if batch_size < 1:
        raise ValueError("batch_size must be positive")
    if max_batches is not None and max_batches < 0:
        raise ValueError("max_batches must not be negative")
    manager = KeyManager(
        master_key=master_key,
        storage_backend=DatabaseStorageBackend(engine, tenant_id),
        tenant_id=tenant_id,
    )
    run_id, targets = _start(engine, manager, tenant_id, resume)
    report = RotationReport(
        tenant_id=tenant_id,
        run_id=run_id,
        resumed=resume,
        target_encryption_key_id=targets[0],
        target_search_key_id=targets[1],
    )
    _Rotation(engine, master_key, manager, report).run(batch_size, max_batches)
    return report


def _start(
    engine: Engine, manager: KeyManager, tenant_id: str, resume: bool
) -> tuple[str, tuple[str, str]]:
    """Claim or resume the tenant's rotation and return ``(run_id, (encryption, search))``."""
    with engine.connect() as conn:
        row = conn.execute(
            select(key_rotations_table).where(key_rotations_table.c.tenant_id == tenant_id)
        ).one_or_none()
    if resume:
        if row is None:
            raise NoRotationInProgressError(f"Tenant {tenant_id!r} has no rotation in progress")
        run_id = row.run_id
        targets = (row.target_encryption_key_id, row.target_search_key_id)
    else:
        if row is not None:
            raise RotationInProgressError(
                f"Tenant {tenant_id!r} has a rotation in progress (run {row.run_id}); resume it"
            )
        run_id = uuid.uuid4().hex
        try:
            with engine.begin() as conn:
                conn.execute(
                    insert(key_rotations_table).values(
                        tenant_id=tenant_id,
                        run_id=run_id,
                        target_encryption_key_id="",
                        target_search_key_id="",
                    )
                )
        except IntegrityError:
            raise RotationInProgressError(
                f"Tenant {tenant_id!r} has a rotation in progress; resume it"
            ) from None
        targets = ("", "")

    if not all(targets):
        # A new run, or one that stopped before recording its successor keys.
        successors = manager.begin_rotation((ENCRYPTION_KEY_TYPE, SEARCH_KEY_TYPE))
        targets = (successors[ENCRYPTION_KEY_TYPE], successors[SEARCH_KEY_TYPE])
        with engine.begin() as conn:
            conn.execute(
                update(key_rotations_table)
                .where(
                    key_rotations_table.c.tenant_id == tenant_id,
                    key_rotations_table.c.run_id == run_id,
                )
                .values(
                    target_encryption_key_id=targets[0],
                    target_search_key_id=targets[1],
                    updated_at=func.now(),
                )
            )
    return run_id, targets


class _Rotation:
    def __init__(
        self, engine: Engine, master_key: bytes, manager: KeyManager, report: RotationReport
    ):
        self._engine = engine
        self._manager = manager
        self._report = report
        self._tenant_id = report.tenant_id
        self._audit_key = derive_audit_key(master_key, report.tenant_id)
        self._encryption_target = report.target_encryption_key_id
        self._search_target = report.target_search_key_id
        self._failed: set[str] = set()

    def run(self, batch_size: int, max_batches: int | None) -> None:
        report = self._report
        for _ in range(MAX_FINISH_ROUNDS):
            if not self._reencrypt(batch_size, max_batches):
                report.stopped_early = True
                break
            if self._failed:
                break  # retiring keys while a document cannot be read would lose it
            if self._finish():
                break

        report.failed_documents = len(self._failed)
        report.failed_doc_ids = sorted(self._failed)[:MAX_REPORTED_DOC_IDS]
        report.unverified_documents = self._count(self._unverified())
        report.complete = (
            not report.stopped_early and not self._failed and self._count(self._stale()) == 0
        )
        if report.complete:
            with self._engine.begin() as conn:
                conn.execute(
                    delete(key_rotations_table).where(
                        key_rotations_table.c.tenant_id == self._tenant_id,
                        key_rotations_table.c.run_id == report.run_id,
                    )
                )

    # -- selection ---------------------------------------------------------------------

    def _stale(self) -> Any:
        """Documents that can still move: an old document key, or an old search key with
        known keywords."""
        docs = documents_table.c
        return or_(
            docs.encryption_key_id != self._encryption_target,
            and_(docs.search_key_id != self._search_target, docs.encrypted_keywords.is_not(None)),
        )

    def _unverified(self) -> Any:
        docs = documents_table.c
        return and_(docs.search_key_id != self._search_target, docs.encrypted_keywords.is_(None))

    def _count(self, condition: Any) -> int:
        with self._engine.connect() as conn:
            return int(
                conn.execute(
                    select(func.count())
                    .select_from(documents_table)
                    .where(documents_table.c.tenant_id == self._tenant_id, condition)
                ).scalar_one()
            )

    # -- re-encryption -----------------------------------------------------------------

    def _reencrypt(self, batch_size: int, max_batches: int | None) -> bool:
        """Run passes until one makes no progress. False if ``max_batches`` stopped it."""
        while True:
            progress = False
            cursor = ""
            while True:
                if max_batches is not None and self._report.batches >= max_batches:
                    return False
                with self._engine.connect() as conn:
                    rows = conn.execute(
                        select(documents_table)
                        .where(
                            documents_table.c.tenant_id == self._tenant_id,
                            documents_table.c.doc_id > cursor,
                            self._stale(),
                        )
                        .order_by(documents_table.c.doc_id)
                        .limit(batch_size)
                    ).all()
                if not rows:
                    break
                progress = self._process_batch(rows) or progress
                self._report.batches += 1
                cursor = rows[-1].doc_id
            if not progress:
                return True

    def _process_batch(self, rows: Sequence[Any]) -> bool:
        """Re-encrypt one batch. Returns True if any row changed.

        Every read and decryption happens first; the write transaction then only swaps rows
        whose ciphertext is still the one that was read, so nothing in it waits on another
        connection.
        """
        planned = [plan for plan in (self._plan(row) for row in rows) if plan is not None]
        reencrypted = retokenized = 0
        with self._engine.begin() as conn:
            for row, values, tokens in planned:
                swapped = conn.execute(
                    update(documents_table)
                    .where(
                        documents_table.c.tenant_id == self._tenant_id,
                        documents_table.c.doc_id == row.doc_id,
                        documents_table.c.encrypted_document == row.encrypted_document,
                    )
                    .values(metadata_json={}, **values)
                )
                if swapped.rowcount != 1:
                    continue  # deleted or rewritten since it was read; the next pass decides
                if tokens is not None:
                    self._replace_tokens(conn, row.doc_id, tokens)
                    retokenized += 1
                reencrypted += 1

            if reencrypted:
                audit.append(
                    conn,
                    self._tenant_id,
                    AuditEvent(
                        AuditEventType.DOCUMENT_REENCRYPT,
                        ACTOR,
                        True,
                        details={
                            "run_id": self._report.run_id,
                            "documents": reencrypted,
                            "retokenized": retokenized,
                            "encryption_key_id": self._encryption_target,
                            "search_key_id": self._search_target,
                        },
                    ),
                    self._audit_key,
                )
            conn.execute(
                update(key_rotations_table)
                .where(key_rotations_table.c.tenant_id == self._tenant_id)
                .values(updated_at=func.now())
            )
        self._report.documents_reencrypted += reencrypted
        self._report.documents_retokenized += retokenized
        return reencrypted > 0

    def _plan(self, row: Any) -> tuple[Any, dict[str, Any], set[str] | None] | None:
        """Decrypt ``row`` and seal it under the target keys.

        Returns ``(row, column values, new tokens or None)``, or None if the row does not
        decrypt (it is recorded as failed and keeps its key).
        """
        try:
            opened = open_document(self._manager, self._tenant_id, row, content=True, keywords=True)
            keywords = opened.keywords
            if keywords is None:
                keywords = self._verified_keywords(row, opened.plaintext)
        except _UNREADABLE:
            self._failed.add(row.doc_id)
            return None
        self._failed.discard(row.doc_id)

        values = seal_document(
            self._manager.get_key_for_decryption(self._encryption_target),
            self._encryption_target,
            self._tenant_id,
            row.doc_id,
            opened.plaintext,
            opened.metadata,
            keywords,
        )
        tokens: set[str] | None = None
        if keywords is not None and row.search_key_id != self._search_target:
            search_key = self._manager.get_key_for_decryption(self._search_target)
            tokens = {search_token(search_key, keyword) for keyword in keywords}
            values.update(search_key_id=self._search_target, token_count=len(tokens))
        return row, values, tokens

    def _verified_keywords(self, row: Any, plaintext: str) -> list[str] | None:
        """Keywords re-extracted from the content, if they reproduce the stored tokens exactly."""
        with self._engine.connect() as conn:
            stored: set[str] = set(
                conn.execute(
                    select(document_tokens_table.c.token).where(
                        document_tokens_table.c.tenant_id == self._tenant_id,
                        document_tokens_table.c.doc_id == row.doc_id,
                    )
                ).scalars()
            )
        try:
            old_search_key = self._manager.get_key_for_decryption(row.search_key_id)
        except _UNREADABLE:
            return None
        candidates = extract_keywords(plaintext)
        if {search_token(old_search_key, keyword) for keyword in candidates} != stored:
            return None
        return sorted(candidates)

    def _replace_tokens(self, conn: Connection, doc_id: str, tokens: set[str]) -> None:
        conn.execute(
            delete(document_tokens_table).where(
                document_tokens_table.c.tenant_id == self._tenant_id,
                document_tokens_table.c.doc_id == doc_id,
            )
        )
        if tokens:
            conn.execute(
                insert(document_tokens_table),
                [
                    {"tenant_id": self._tenant_id, "token": token, "doc_id": doc_id}
                    for token in sorted(tokens)
                ],
            )

    # -- finishing ---------------------------------------------------------------------

    def _finish(self) -> bool:
        """Retire or destroy every old key no document references.

        Returns True when no document can move any more (a concurrent write may have added
        one under an old key, which needs another pass).
        """
        self._manager.refresh()
        targets = {self._encryption_target, self._search_target}
        old_keys = sorted(
            (
                (metadata.key_id, metadata.key_type)
                for metadata in (
                    self._manager.get_metadata(key_id)
                    for key_id in self._manager.list_keys(active_only=False)
                )
                if metadata.key_type in (ENCRYPTION_KEY_TYPE, SEARCH_KEY_TYPE)
                and metadata.key_id not in targets
                and metadata.lifecycle_state == KeyLifecycleState.ROTATING
            ),
        )
        self._report.still_referenced = {}
        for key_id, key_type in old_keys:
            self._retire_if_unreferenced(key_id, key_type)
        return self._count(self._stale()) == 0

    def _retire_if_unreferenced(self, key_id: str, key_type: str) -> None:
        keys = key_store_table.c
        is_search_key = key_type == SEARCH_KEY_TYPE
        column = (
            documents_table.c.search_key_id
            if is_search_key
            else documents_table.c.encryption_key_id
        )
        with self._engine.begin() as conn:
            # Lock the key row before counting: a write holding it FOR SHARE (see
            # require_writable_keys) commits first and is counted, or sees the new state.
            conn.execute(
                update(key_store_table)
                .where(keys.tenant_id == self._tenant_id, keys.key_id == key_id)
                .values(updated_at=func.now())
            )
            references = conn.execute(
                select(func.count())
                .select_from(documents_table)
                .where(documents_table.c.tenant_id == self._tenant_id, column == key_id)
            ).scalar_one()
            if references:
                self._report.still_referenced[key_id] = int(references)
                return
            stored: dict[str, Any] = conn.execute(
                select(keys.metadata_json).where(
                    keys.tenant_id == self._tenant_id, keys.key_id == key_id
                )
            ).scalar_one()
            state = KeyLifecycleState.DESTROYED if is_search_key else KeyLifecycleState.RETIRED
            values: dict[str, Any] = {
                "metadata_json": {**json.loads(json.dumps(stored)), "lifecycle_state": state},
            }
            values["metadata_json"]["active"] = False
            if is_search_key:
                values["encrypted_key"] = b""  # crypto-shred: its tokens are gone
            conn.execute(
                update(key_store_table)
                .where(keys.tenant_id == self._tenant_id, keys.key_id == key_id)
                .values(**values)
            )
            audit.append(
                conn,
                self._tenant_id,
                AuditEvent(
                    AuditEventType.KEY_DESTROY if is_search_key else AuditEventType.KEY_RETIRE,
                    ACTOR,
                    True,
                    key_id,
                    {"run_id": self._report.run_id},
                    key_id=key_id,
                ),
                self._audit_key,
            )
        (self._report.destroyed_keys if is_search_key else self._report.retired_keys).append(key_id)
