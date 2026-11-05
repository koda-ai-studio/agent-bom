"""Count dispatch claims so a job that crashes every worker cannot loop forever.

Rows already in the queue start at zero. Replicas on the previous release ignore
the column and the request-owned rows newer replicas write.

Revision ID: 20261105_02
Revises: 20261105_01
"""

from __future__ import annotations

from alembic import op

revision = "20261105_02"
down_revision = "20261105_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE scan_dispatch_queue ADD COLUMN IF NOT EXISTS attempts INTEGER NOT NULL DEFAULT 0")
    op.execute("UPDATE control_plane_schema_versions SET version=5,updated_at=now() WHERE component='scan_jobs' AND version < 5")


def downgrade() -> None:
    op.execute("ALTER TABLE scan_dispatch_queue DROP COLUMN IF EXISTS attempts")
