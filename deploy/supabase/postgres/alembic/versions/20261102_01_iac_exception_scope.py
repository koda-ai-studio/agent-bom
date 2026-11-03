"""Scope tenant exceptions to IaC findings: rule id, path glob and resource selector.

Additive and idempotent: three ``TEXT NOT NULL DEFAULT ''`` columns, so existing
vulnerability exceptions keep their meaning and older writers stay compatible.
The table keeps its ``team_id`` row-level-security policy; no new table, index or
policy is created. Must match the ``ALTER TABLE exceptions`` lines in
``runtime-schema.sql``.
"""

from alembic import op

revision = "20261102_01"
down_revision = "20261027_03"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        DO $$
        BEGIN
            IF to_regclass('exceptions') IS NOT NULL THEN
                ALTER TABLE exceptions ADD COLUMN IF NOT EXISTS iac_rule_id TEXT NOT NULL DEFAULT '';
                ALTER TABLE exceptions ADD COLUMN IF NOT EXISTS iac_path TEXT NOT NULL DEFAULT '';
                ALTER TABLE exceptions ADD COLUMN IF NOT EXISTS iac_resource TEXT NOT NULL DEFAULT '';
                UPDATE control_plane_schema_versions SET version=4,updated_at=now()
                    WHERE component='exceptions' AND version < 4;
            END IF;
        END
        $$
    """)


def downgrade() -> None:
    raise NotImplementedError("Retain IaC exception scope: it is audit evidence of what was approved. Restore a reviewed backup.")
