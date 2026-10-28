"""Tamper-evident audit log: one entry schema and a per-tenant HMAC hash chain.

Every audit row (API events, rejected requests and key events) uses the same entry schema,
version :data:`SCHEMA_VERSION`::

    {schema_version, seq, tenant_id, timestamp, event_type, actor, success,
     resource, details, request_id}

``details`` passes through :func:`encrypted_ir.redaction.redact` before it is stored, so
plaintext, queries, tokens and key material are never written.

Each tenant's rows form a chain. Row ``seq`` stores the previous row's hash as ``prev_hash``
(64 zeros for ``seq`` 1) and::

    entry_hash = HMAC-SHA256(audit_key, prev_hash || canonical_json(entry))

where ``audit_key`` is derived from the app master key and the tenant ID. Editing, deleting,
reordering or moving a row between tenants breaks the chain, and the
``encrypted_ir_audit_chain_heads`` row (last ``seq`` and hash per tenant) catches a truncated
tail unless the head row is rewritten too. Someone who holds the master key can rebuild a valid
chain. Against both, export the head (``python -m encrypted_ir.tools.export_audit``) to storage
the database's writers cannot change, and check it with ``--check-head`` on later exports.

:func:`append` runs inside the caller's transaction and takes the per-tenant head-row lock as its
last step, so an operation and its audit row commit or roll back together and concurrent
appends for one tenant are serialized.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import insert, select, update
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.engine import Connection

from .database import audit_chain_heads_table, audit_log_table
from .logging import current_correlation_id
from .redaction import redact

SCHEMA_VERSION = 1
GENESIS_HASH = "0" * 64
_AUDIT_KEY_LABEL = b"encrypted-ir/audit-chain/v1"


class AuditEventType(StrEnum):
    """Event types written to the audit log."""

    DOCUMENT_ENCRYPT = "document.encrypt"
    DOCUMENT_SEARCH = "document.search"
    DOCUMENT_DECRYPT = "document.decrypt"
    DOCUMENT_DELETE = "document.delete"
    RAG_RETRIEVE = "rag.retrieve"
    AUTH_FAILURE = "auth.failure"
    AUTHZ_FAILURE = "authz.failure"
    RATE_LIMIT_EXCEEDED = "rate_limit.exceeded"
    KEY_CREATE = "key.create"
    KEY_READ = "key.read"
    KEY_ROTATE = "key.rotate"
    KEY_DEACTIVATE = "key.deactivate"
    KEY_IMPORT = "key.import"
    KEY_UNWRAP = "key.unwrap"


@dataclass(frozen=True)
class AuditEvent:
    """What happened. ``request_id`` defaults to the current logging correlation ID."""

    event_type: str
    actor: str
    success: bool
    resource: str = ""
    details: Mapping[str, Any] = field(default_factory=dict)
    request_id: str | None = None
    key_id: str | None = None


@dataclass(frozen=True)
class AuditWrite:
    """An event plus the tenant's audit key, handed to a storage backend to append."""

    event: AuditEvent
    audit_key: bytes = field(repr=False)


@dataclass(frozen=True)
class AppendedEntry:
    """The chain position of an appended row."""

    seq: int
    entry_hash: str


@dataclass(frozen=True)
class ChainVerification:
    """Result of :func:`verify_chain`."""

    ok: bool
    entries: int
    head_seq: int
    head_hash: str
    first_bad_seq: int | None = None
    reason: str = ""


def _length_prefixed(*parts: bytes | str) -> bytes:
    out = b""
    for part in parts:
        data = part.encode() if isinstance(part, str) else part
        out += len(data).to_bytes(4, "big") + data
    return out


def derive_audit_key(master_key: bytes, tenant_id: str) -> bytes:
    """Per-tenant HMAC key for the audit chain, derived from the app master key with HKDF."""
    key: bytes = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_length_prefixed(_AUDIT_KEY_LABEL, tenant_id),
    ).derive(master_key)
    return key


def canonical_json(entry: Mapping[str, Any]) -> bytes:
    """Deterministic JSON encoding used for hashing."""
    return json.dumps(
        entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()


def entry_hash(audit_key: bytes, prev_hash: str, entry: Mapping[str, Any]) -> str:
    """``HMAC-SHA256(audit_key, prev_hash || canonical_json(entry))`` as hex."""
    return hmac.new(
        audit_key, bytes.fromhex(prev_hash) + canonical_json(entry), hashlib.sha256
    ).hexdigest()


def _insert_head_if_missing(conn: Connection, tenant_id: str) -> None:
    values = {"tenant_id": tenant_id, "seq": 0, "entry_hash": GENESIS_HASH}
    dialect = conn.dialect.name
    if dialect == "postgresql":
        statement: Any = postgresql.insert(audit_chain_heads_table).values(**values)
    elif dialect == "sqlite":
        statement = sqlite.insert(audit_chain_heads_table).values(**values)
    else:  # pragma: no cover - only PostgreSQL and SQLite are supported
        raise NotImplementedError(f"Audit chain is not implemented for {dialect}")
    conn.execute(statement.on_conflict_do_nothing(index_elements=["tenant_id"]))


def append(conn: Connection, tenant_id: str, event: AuditEvent, audit_key: bytes) -> AppendedEntry:
    """Append ``event`` to ``tenant_id``'s chain inside the caller's transaction.

    Call it last in the transaction: the head-row update locks the tenant's chain until the
    transaction ends, so concurrent appends for one tenant queue behind it.
    """
    _insert_head_if_missing(conn, tenant_id)
    seq, prev_hash = conn.execute(
        update(audit_chain_heads_table)
        .where(audit_chain_heads_table.c.tenant_id == tenant_id)
        .values(seq=audit_chain_heads_table.c.seq + 1)
        .returning(audit_chain_heads_table.c.seq, audit_chain_heads_table.c.entry_hash)
    ).one()

    request_id = event.request_id if event.request_id is not None else current_correlation_id()
    entry = {
        "schema_version": SCHEMA_VERSION,
        "seq": seq,
        "tenant_id": tenant_id,
        "timestamp": datetime.now(UTC).isoformat(timespec="microseconds"),
        "event_type": str(event.event_type),
        "actor": event.actor,
        "success": event.success,
        "resource": event.resource,
        "details": redact(dict(event.details)),
        "request_id": request_id or "",
    }
    digest = entry_hash(audit_key, prev_hash, entry)
    conn.execute(
        insert(audit_log_table).values(
            tenant_id=tenant_id,
            key_id=event.key_id,
            entry_json=entry,
            schema_version=SCHEMA_VERSION,
            event_type=entry["event_type"],
            actor=entry["actor"],
            request_id=entry["request_id"],
            success=entry["success"],
            seq=seq,
            prev_hash=prev_hash,
            entry_hash=digest,
        )
    )
    conn.execute(
        update(audit_chain_heads_table)
        .where(audit_chain_heads_table.c.tenant_id == tenant_id)
        .values(entry_hash=digest)
    )
    return AppendedEntry(seq=seq, entry_hash=digest)


def load_chain(conn: Connection, tenant_id: str) -> tuple[list[Any], Any | None]:
    """Return ``(rows, head)`` for ``tenant_id``: chained rows in ``seq`` order and the head row."""
    rows = conn.execute(
        select(audit_log_table)
        .where(audit_log_table.c.tenant_id == tenant_id, audit_log_table.c.seq.is_not(None))
        .order_by(audit_log_table.c.seq)
    ).all()
    head = conn.execute(
        select(audit_chain_heads_table).where(audit_chain_heads_table.c.tenant_id == tenant_id)
    ).one_or_none()
    return list(rows), head


_DENORMALIZED = ("schema_version", "event_type", "actor", "request_id", "success")


def _row_problem(
    row: Any, expected_seq: int, prev_hash: str, tenant_id: str, audit_key: bytes
) -> str | None:
    """Why ``row`` cannot be entry ``expected_seq`` after ``prev_hash``, or None if it can."""
    entry = row.entry_json
    if row.seq != expected_seq:
        return f"expected seq {expected_seq}, found {row.seq} (missing or reordered)"
    if row.prev_hash != prev_hash:
        return "prev_hash does not link to the previous entry"
    if entry.get("seq") != row.seq or entry.get("tenant_id") != tenant_id:
        return "entry seq or tenant does not match its row"
    if any(entry.get(name) != getattr(row, name) for name in _DENORMALIZED):
        return "a column does not match the hashed entry"
    if not hmac.compare_digest(entry_hash(audit_key, prev_hash, entry), row.entry_hash or ""):
        return "entry_hash does not match the entry"
    return None


def verify_chain(
    rows: Iterable[Any], head: Any | None, tenant_id: str, audit_key: bytes
) -> ChainVerification:
    """Check a tenant's chain: contiguous ``seq``, links, HMACs, columns, and the head row.

    On failure, ``entries``, ``head_seq`` and ``head_hash`` describe the verified prefix.
    """
    prev_hash = GENESIS_HASH
    count = 0
    for expected_seq, row in enumerate(rows, start=1):
        problem = _row_problem(row, expected_seq, prev_hash, tenant_id, audit_key)
        if problem is not None:
            return ChainVerification(
                False, count, count, prev_hash, first_bad_seq=expected_seq, reason=problem
            )
        count = expected_seq
        prev_hash = row.entry_hash

    if head is None:
        if count:
            return ChainVerification(False, count, count, prev_hash, None, "chain head is missing")
        return ChainVerification(True, 0, 0, GENESIS_HASH)
    if head.seq != count or head.entry_hash != prev_hash:
        return ChainVerification(
            False,
            count,
            count,
            prev_hash,
            count + 1,
            f"chain head is at seq {head.seq}; rows end at seq {count} (truncated or edited)",
        )
    return ChainVerification(True, count, count, prev_hash)
