"""Key rotation: sealed keyword lists, key-ID indexes and a per-tenant rotation lock.

Adds encrypted_ir_documents.encrypted_keywords (the sealed keyword list, so rotation can rebuild
search tokens under a new key), indexes on (tenant_id, encryption_key_id) and (tenant_id,
search_key_id), and encrypted_ir_key_rotations, whose primary key allows one rotation per tenant
at a time. Rows ingested before this revision have no sealed keywords; the rotation tool
re-extracts them from the content when the stored tokens confirm it.

Revision ID: 20261028_0005
Revises: 20261027_0004
Create Date: 2026-10-28
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261028_0005"
down_revision = "20261027_0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("encrypted_ir_documents") as batch_op:
        batch_op.add_column(sa.Column("encrypted_keywords", sa.LargeBinary(), nullable=True))
    op.create_index(
        "ix_encrypted_ir_documents_tenant_encryption_key",
        "encrypted_ir_documents",
        ["tenant_id", "encryption_key_id"],
    )
    op.create_index(
        "ix_encrypted_ir_documents_tenant_search_key",
        "encrypted_ir_documents",
        ["tenant_id", "search_key_id"],
    )
    op.create_table(
        "encrypted_ir_key_rotations",
        sa.Column("tenant_id", sa.String(length=255), primary_key=True),
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("target_encryption_key_id", sa.String(length=255), nullable=False),
        sa.Column("target_search_key_id", sa.String(length=255), nullable=False),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_table("encrypted_ir_key_rotations")
    op.drop_index(
        "ix_encrypted_ir_documents_tenant_search_key", table_name="encrypted_ir_documents"
    )
    op.drop_index(
        "ix_encrypted_ir_documents_tenant_encryption_key", table_name="encrypted_ir_documents"
    )
    with op.batch_alter_table("encrypted_ir_documents") as batch_op:
        batch_op.drop_column("encrypted_keywords")
