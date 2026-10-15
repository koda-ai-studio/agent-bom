"""Record the node ids asset canonicalization replaced, per tenant.

When several sources observe one asset the graph keeps a single canonical
node; the ids those sources minted become aliases so references recorded by
earlier snapshots, trace claims and saved links still resolve.

Revision ID: 20261014_01
Revises: 20261013_02
"""

from alembic import op

revision = "20261014_01"
down_revision = "20261013_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS graph_node_aliases (
            tenant_id TEXT NOT NULL DEFAULT 'default',
            alias_id TEXT NOT NULL,
            canonical_id TEXT NOT NULL,
            entity_type TEXT NOT NULL DEFAULT '',
            identity_version TEXT NOT NULL DEFAULT '',
            scan_id TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (tenant_id, alias_id)
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_pg_graph_node_aliases_canonical ON graph_node_aliases(tenant_id, canonical_id)")
    op.execute("ALTER TABLE graph_node_aliases ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE graph_node_aliases FORCE ROW LEVEL SECURITY")
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_policy p
                WHERE p.polrelid = to_regclass('graph_node_aliases')
                  AND p.polname = 'graph_node_aliases_tenant_isolation'
            ) THEN
                CREATE POLICY graph_node_aliases_tenant_isolation ON graph_node_aliases
                    USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant())
                    WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_app') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE ON graph_node_aliases TO agent_bom_app;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_rls_maintenance') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE ON graph_node_aliases TO agent_bom_rls_maintenance;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_readonly') THEN
                GRANT SELECT ON graph_node_aliases TO agent_bom_readonly;
            END IF;
        END
        $$
    """)
    op.execute("""
        UPDATE control_plane_schema_versions SET version=9,updated_at=now()
        WHERE component='graph' AND version=8
    """)


def downgrade() -> None:
    # Older runtimes neither write nor read aliases; dropping the table only
    # loses the mapping for ids replaced by canonicalization.
    op.execute("DROP TABLE IF EXISTS graph_node_aliases")
    op.execute("UPDATE control_plane_schema_versions SET version=8,updated_at=now() WHERE component='graph' AND version=9")
