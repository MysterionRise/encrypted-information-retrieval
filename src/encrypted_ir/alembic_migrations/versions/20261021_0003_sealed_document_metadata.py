"""Add encrypted_metadata for context-bound sealed documents.

Rows written from this version on store content and metadata sealed with AES-256-GCM and bound
to their tenant, document and key (algorithm "aes-256-gcm/v1"). Existing rows keep algorithm
"aes-gcm", their legacy ciphertext and their plaintext metadata_json, and stay readable.

Revision ID: 20261021_0003
Revises: 20261021_0002
Create Date: 2026-10-21
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261021_0003"
down_revision = "20261021_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("encrypted_ir_documents") as batch_op:
        batch_op.add_column(sa.Column("encrypted_metadata", sa.LargeBinary(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("encrypted_ir_documents") as batch_op:
        batch_op.drop_column("encrypted_metadata")
