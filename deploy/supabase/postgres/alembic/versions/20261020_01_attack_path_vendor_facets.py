"""Store each attack path's endpoint vendors for the indexed cross-vendor queue.

The cross-vendor queue classified every stored path on every request.
``source_vendor`` / ``target_vendor`` are fixed at persist (derivation
version 7), so the page and its vendor-pair facets are indexed reads. Rows
written before this revision belong to snapshots whose derivation version is
older; readers already treat those snapshots as having no current index.

Revision ID: 20261020_01
Revises: 20261015_01
"""

from alembic import op

revision = "20261020_01"
down_revision = "20261015_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE graph_attack_paths ADD COLUMN IF NOT EXISTS source_vendor TEXT NOT NULL DEFAULT ''")
    op.execute("ALTER TABLE graph_attack_paths ADD COLUMN IF NOT EXISTS target_vendor TEXT NOT NULL DEFAULT ''")
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_pg_graph_attack_paths_vendor "
        "ON graph_attack_paths(tenant_id, scan_id, source_vendor, target_vendor, queue_rank)"
    )
    op.execute("""
        UPDATE control_plane_schema_versions SET version=11,updated_at=now()
        WHERE component='graph' AND version=10
    """)


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_pg_graph_attack_paths_vendor")
    op.execute("ALTER TABLE graph_attack_paths DROP COLUMN IF EXISTS target_vendor")
    op.execute("ALTER TABLE graph_attack_paths DROP COLUMN IF EXISTS source_vendor")
    op.execute("UPDATE control_plane_schema_versions SET version=10,updated_at=now() WHERE component='graph' AND version=11")
