"""Drop the never-set documents.deleted flag.

Documents are hard-deleted together with their tokens, so the soft-delete flag was always
false. Removing it keeps the schema honest about how deletion works.

Revision ID: 20261021_0002
Revises: 20260706_0001
Create Date: 2026-10-21
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261021_0002"
down_revision = "20260706_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # batch_alter_table recreates the table on SQLite, which cannot drop columns in place.
    with op.batch_alter_table("encrypted_ir_documents") as batch_op:
        batch_op.drop_column("deleted")


def downgrade() -> None:
    with op.batch_alter_table("encrypted_ir_documents") as batch_op:
        batch_op.add_column(
            sa.Column("deleted", sa.Boolean(), nullable=False, server_default=sa.false())
        )
