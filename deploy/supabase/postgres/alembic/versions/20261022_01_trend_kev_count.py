"""Persist nullable active KEV issue counts without inventing legacy history.

Rollback lowers the runtime version requirement but retains the additive column
and its measurements. Previous application versions ignore this column; a later
upgrade preserves the recorded evidence.
"""

from alembic import op

revision = "20261022_01"
down_revision = "20261020_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        DO $$ BEGIN
            IF to_regclass('public.trend_history') IS NOT NULL THEN
                ALTER TABLE trend_history ADD COLUMN IF NOT EXISTS kev_count INTEGER CHECK (kev_count >= 0);
                UPDATE control_plane_schema_versions SET version=3,updated_at=now()
                WHERE component='trend_history' AND version < 3;
            END IF;
        END $$
    """)


def downgrade() -> None:
    op.execute("UPDATE control_plane_schema_versions SET version=2,updated_at=now() WHERE component='trend_history' AND version=3")
