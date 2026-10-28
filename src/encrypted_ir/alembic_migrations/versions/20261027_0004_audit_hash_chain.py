"""Audit log: one entry schema and a per-tenant HMAC hash chain.

Adds the chain columns to encrypted_ir_audit_log (schema_version, event_type, actor, request_id,
success, seq, prev_hash, entry_hash), a unique (tenant_id, seq) index, an index on created_at,
and encrypted_ir_audit_chain_heads with each tenant's last seq and hash. Rows written before this
revision keep NULL chain columns and are not part of any chain; the export tool reports them
separately.

Revision ID: 20261027_0004
Revises: 20261021_0003
Create Date: 2026-10-27
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261027_0004"
down_revision = "20261021_0003"
branch_labels = None
depends_on = None

_COLUMNS = (
    ("schema_version", sa.Integer()),
    ("event_type", sa.String(length=64)),
    ("actor", sa.String(length=255)),
    ("request_id", sa.String(length=64)),
    ("success", sa.Boolean()),
    ("seq", sa.BigInteger()),
    ("prev_hash", sa.String(length=64)),
    ("entry_hash", sa.String(length=64)),
)


def upgrade() -> None:
    with op.batch_alter_table("encrypted_ir_audit_log") as batch_op:
        for name, column_type in _COLUMNS:
            batch_op.add_column(sa.Column(name, column_type, nullable=True))
    op.create_index(
        "uq_encrypted_ir_audit_log_tenant_seq",
        "encrypted_ir_audit_log",
        ["tenant_id", "seq"],
        unique=True,
    )
    op.create_index(
        "ix_encrypted_ir_audit_log_created_at", "encrypted_ir_audit_log", ["created_at"]
    )
    op.create_table(
        "encrypted_ir_audit_chain_heads",
        sa.Column("tenant_id", sa.String(length=255), primary_key=True),
        sa.Column("seq", sa.BigInteger(), nullable=False),
        sa.Column("entry_hash", sa.String(length=64), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("encrypted_ir_audit_chain_heads")
    op.drop_index("ix_encrypted_ir_audit_log_created_at", table_name="encrypted_ir_audit_log")
    op.drop_index("uq_encrypted_ir_audit_log_tenant_seq", table_name="encrypted_ir_audit_log")
    with op.batch_alter_table("encrypted_ir_audit_log") as batch_op:
        for name, _ in reversed(_COLUMNS):
            batch_op.drop_column(name)
