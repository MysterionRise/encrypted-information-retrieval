"""Database schema helpers for durable API workflows."""

from __future__ import annotations

from typing import Any

from sqlalchemy import (
    JSON,
    Column,
    DateTime,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    create_engine,
    event,
    func,
)
from sqlalchemy.engine import Engine
from sqlalchemy.pool import StaticPool

metadata = MetaData()

key_store_table = Table(
    "encrypted_ir_keys",
    metadata,
    Column("tenant_id", String(255), primary_key=True),
    Column("key_id", String(255), primary_key=True),
    Column("encrypted_key", LargeBinary, nullable=False),
    Column("metadata_json", JSON, nullable=False),
    Column(
        "updated_at",
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    ),
)

audit_log_table = Table(
    "encrypted_ir_audit_log",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("tenant_id", String(255), nullable=False, index=True),
    Column("key_id", String(255), nullable=True, index=True),
    Column("entry_json", JSON, nullable=False),
    Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
)

documents_table = Table(
    "encrypted_ir_documents",
    metadata,
    Column("tenant_id", String(255), primary_key=True),
    Column("doc_id", String(255), primary_key=True),
    Column("encrypted_document", LargeBinary, nullable=False),
    # Sealed metadata for "aes-256-gcm/v1" rows; NULL for legacy "aes-gcm" rows, whose
    # metadata stays in metadata_json.
    Column("encrypted_metadata", LargeBinary, nullable=True),
    Column("algorithm", String(64), nullable=False, default="aes-gcm"),
    Column("encryption_key_id", String(255), nullable=False),
    Column("search_key_id", String(255), nullable=False),
    Column("metadata_json", JSON, nullable=False, default=dict),
    Column("token_count", Integer, nullable=False, default=0),
    Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
    Column(
        "updated_at",
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    ),
)

document_tokens_table = Table(
    "encrypted_ir_document_tokens",
    metadata,
    Column("tenant_id", String(255), primary_key=True),
    Column("token", Text, primary_key=True),
    Column("doc_id", String(255), primary_key=True),
    UniqueConstraint("tenant_id", "doc_id", "token", name="uq_encrypted_ir_doc_token"),
)


def create_database_engine(database_url: str) -> Engine:
    """Create a SQLAlchemy engine for ``database_url``.

    Bound parameters are hidden from exception messages (``hide_parameters``), so a failed
    statement never prints ciphertext, search tokens or tenant IDs into logs. In-memory SQLite
    shares one connection between threads and is for tests only. File SQLite waits up to 30 s
    for locks and uses WAL so readers and a writer can run concurrently.
    """
    if database_url == "sqlite+pysqlite:///:memory:":
        return create_engine(
            database_url,
            future=True,
            hide_parameters=True,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
    if database_url.startswith("sqlite"):
        engine = create_engine(
            database_url,
            future=True,
            hide_parameters=True,
            connect_args={"check_same_thread": False, "timeout": 30},
        )
        event.listen(engine, "connect", _sqlite_wal)
        return engine
    return create_engine(database_url, future=True, hide_parameters=True)


def _sqlite_wal(dbapi_connection: Any, _connection_record: Any) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.close()


def create_database_schema(engine: Engine) -> None:
    """Create all durable workflow tables."""
    metadata.create_all(engine)
