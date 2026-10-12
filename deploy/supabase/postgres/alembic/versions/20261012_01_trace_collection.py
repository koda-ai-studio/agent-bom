"""Add tenant-bound trace collection checkpoints and bounded replay receipts."""

from alembic import op

from agent_bom.api.trace_collection.schema import POSTGRES_TRACE_COLLECTION_V1

revision = "20261012_01"
down_revision = "20261010_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(POSTGRES_TRACE_COLLECTION_V1)


def downgrade() -> None:
    raise NotImplementedError("Disable collection for rollback; retain runtime evidence and checkpoints")
