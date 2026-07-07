"""Database schema helpers for durable API workflows."""

from __future__ import annotations

from sqlalchemy import (
    JSON,
    Boolean,
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
    Column("updated_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
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
    Column("algorithm", String(64), nullable=False, default="aes-gcm"),
    Column("encryption_key_id", String(255), nullable=False),
    Column("search_key_id", String(255), nullable=False),
    Column("metadata_json", JSON, nullable=False, default=dict),
    Column("token_count", Integer, nullable=False, default=0),
    Column("deleted", Boolean, nullable=False, default=False),
    Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
    Column("updated_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
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
    """Create a SQLAlchemy engine with SQLite in-memory settings when needed."""
    if database_url == "sqlite+pysqlite:///:memory:":
        return create_engine(
            database_url,
            future=True,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
    return create_engine(database_url, future=True)


def create_database_schema(engine: Engine) -> None:
    """Create all durable workflow tables."""
    metadata.create_all(engine)
