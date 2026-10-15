"""Key graph node aliases by snapshot.

An alias binding is evidence recorded by one snapshot. Keyed only by tenant
and alias id, a newer snapshot overwrote the binding an older snapshot
recorded, so resolving an id inside the older snapshot returned the newer
canonical node. Each snapshot now keeps its own binding.

Revision ID: 20261015_01
Revises: 20261014_02
"""

from alembic import op

revision = "20261015_01"
down_revision = "20261014_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        DO $$
        DECLARE pk_name TEXT;
        BEGIN
            SELECT c.conname INTO pk_name FROM pg_constraint c
            WHERE c.conrelid = to_regclass('graph_node_aliases') AND c.contype = 'p';
            IF pk_name IS NOT NULL THEN
                EXECUTE format('ALTER TABLE graph_node_aliases DROP CONSTRAINT %I', pk_name);
            END IF;
            ALTER TABLE graph_node_aliases ADD CONSTRAINT graph_node_aliases_pkey PRIMARY KEY (tenant_id, scan_id, alias_id);
        END
        $$
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_pg_graph_node_aliases_alias ON graph_node_aliases(tenant_id, alias_id, updated_at)")
    op.execute("""
        UPDATE control_plane_schema_versions SET version=10,updated_at=now()
        WHERE component='graph' AND version=9
    """)


def downgrade() -> None:
    # The older key holds one binding per alias: keep each alias's most
    # recently written binding, as the older runtime would have.
    op.execute("DROP INDEX IF EXISTS idx_pg_graph_node_aliases_alias")
    # FORCE RLS applies to the table owner; the dedupe must see every tenant.
    op.execute("SELECT set_config('app.bypass_rls', '1', true)")
    op.execute("""
        DELETE FROM graph_node_aliases a
        USING graph_node_aliases b
        WHERE a.tenant_id = b.tenant_id AND a.alias_id = b.alias_id
          AND (a.updated_at, a.scan_id) < (b.updated_at, b.scan_id)
    """)
    op.execute("ALTER TABLE graph_node_aliases DROP CONSTRAINT IF EXISTS graph_node_aliases_pkey")
    op.execute("ALTER TABLE graph_node_aliases ADD CONSTRAINT graph_node_aliases_pkey PRIMARY KEY (tenant_id, alias_id)")
    op.execute("UPDATE control_plane_schema_versions SET version=9,updated_at=now() WHERE component='graph' AND version=10")
