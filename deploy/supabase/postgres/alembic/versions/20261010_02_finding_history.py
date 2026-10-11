"""Atomically invalidated, versioned retained finding history."""

from alembic import op

from agent_bom.api.storage.finding_history_schema import POSTGRES_FINDING_HISTORY_V1

revision = "20261010_02"
down_revision = "20261010_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(POSTGRES_FINDING_HISTORY_V1)


def downgrade() -> None:
    raise NotImplementedError("Disable snapshot reads and writes for rollback; retain source jobs and reviewed backups")
