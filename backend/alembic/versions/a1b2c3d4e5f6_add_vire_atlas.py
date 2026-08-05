"""Add vire_atlas cache table

Revision ID: a1b2c3d4e5f6
Revises: 88883345033b
Create Date: 2026-08-05 15:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, None] = "88883345033b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "vire_atlas",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("domain", sa.String(), nullable=False),
        sa.Column("scan_mode", sa.String(), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.Column("emails_found", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(), nullable=True),
        sa.Column("hits", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("scanned_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("domain", "scan_mode", name="uq_vire_atlas_domain_mode"),
    )
    op.create_index(op.f("ix_vire_atlas_id"), "vire_atlas", ["id"], unique=False)
    op.create_index(op.f("ix_vire_atlas_domain"), "vire_atlas", ["domain"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_vire_atlas_domain"), table_name="vire_atlas")
    op.drop_index(op.f("ix_vire_atlas_id"), table_name="vire_atlas")
    op.drop_table("vire_atlas")
