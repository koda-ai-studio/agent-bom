"""Durable per-finding lifecycle, kept past scan retention.

Empty tables only, so the upgrade is brief. The control plane's cleanup tick seeds
existing dates from retained scans in bounded batches; reads answer from the
retained reports until it finishes.

Revision ID: 20261105_02
Revises: 20261105_01
"""

from alembic import op

from agent_bom.api.storage.finding_lifecycle_schema import POSTGRES_FINDING_LIFECYCLE_V1

revision = "20261105_02"
down_revision = "20261105_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(POSTGRES_FINDING_LIFECYCLE_V1)


def downgrade() -> None:
    raise NotImplementedError("The lifecycle tables hold dates scans no longer retain; keep them and restore reviewed backups to roll back")
