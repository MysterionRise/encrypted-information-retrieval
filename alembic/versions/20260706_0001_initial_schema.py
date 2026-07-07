"""Initial durable retrieval schema.

Revision ID: 20260706_0001
Revises:
Create Date: 2026-07-06
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260706_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "encrypted_ir_keys",
        sa.Column("tenant_id", sa.String(length=255), nullable=False),
        sa.Column("key_id", sa.String(length=255), nullable=False),
        sa.Column("encrypted_key", sa.LargeBinary(), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("tenant_id", "key_id"),
    )

    op.create_table(
        "encrypted_ir_audit_log",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.String(length=255), nullable=False),
        sa.Column("key_id", sa.String(length=255), nullable=True),
        sa.Column("entry_json", sa.JSON(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_encrypted_ir_audit_log_tenant_id", "encrypted_ir_audit_log", ["tenant_id"])
    op.create_index("ix_encrypted_ir_audit_log_key_id", "encrypted_ir_audit_log", ["key_id"])

    op.create_table(
        "encrypted_ir_documents",
        sa.Column("tenant_id", sa.String(length=255), nullable=False),
        sa.Column("doc_id", sa.String(length=255), nullable=False),
        sa.Column("encrypted_document", sa.LargeBinary(), nullable=False),
        sa.Column("algorithm", sa.String(length=64), nullable=False),
        sa.Column("encryption_key_id", sa.String(length=255), nullable=False),
        sa.Column("search_key_id", sa.String(length=255), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("token_count", sa.Integer(), nullable=False),
        sa.Column("deleted", sa.Boolean(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("tenant_id", "doc_id"),
    )

    op.create_table(
        "encrypted_ir_document_tokens",
        sa.Column("tenant_id", sa.String(length=255), nullable=False),
        sa.Column("token", sa.Text(), nullable=False),
        sa.Column("doc_id", sa.String(length=255), nullable=False),
        sa.PrimaryKeyConstraint("tenant_id", "token", "doc_id"),
        sa.UniqueConstraint("tenant_id", "doc_id", "token", name="uq_encrypted_ir_doc_token"),
    )


def downgrade() -> None:
    op.drop_table("encrypted_ir_document_tokens")
    op.drop_table("encrypted_ir_documents")
    op.drop_index("ix_encrypted_ir_audit_log_key_id", table_name="encrypted_ir_audit_log")
    op.drop_index("ix_encrypted_ir_audit_log_tenant_id", table_name="encrypted_ir_audit_log")
    op.drop_table("encrypted_ir_audit_log")
    op.drop_table("encrypted_ir_keys")
