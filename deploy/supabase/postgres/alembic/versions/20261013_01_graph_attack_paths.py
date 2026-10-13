"""Materialize the complete ranked attack-path set per graph snapshot.

Revision ID: 20261013_01
Revises: 20261012_03
"""

from alembic import op

revision = "20261013_01"
down_revision = "20261012_03"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS graph_attack_paths (
            tenant_id TEXT NOT NULL DEFAULT 'default',
            scan_id TEXT NOT NULL,
            snapshot_generation TEXT NOT NULL DEFAULT '',
            path_key TEXT NOT NULL,
            path_kind TEXT NOT NULL,
            derivation_version INTEGER NOT NULL,
            rank_index INTEGER NOT NULL,
            source_node TEXT NOT NULL,
            target_node TEXT NOT NULL,
            hop_count INTEGER NOT NULL DEFAULT 0,
            composite_risk DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            path_json TEXT NOT NULL,
            computed_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, scan_id, path_key)
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_pg_graph_attack_paths_rank ON graph_attack_paths(tenant_id, scan_id, rank_index)")
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_pg_graph_attack_paths_source ON graph_attack_paths(tenant_id, scan_id, source_node, rank_index)"
    )
    op.execute("ALTER TABLE graph_attack_paths ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE graph_attack_paths FORCE ROW LEVEL SECURITY")
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_policy p
                WHERE p.polrelid = to_regclass('graph_attack_paths')
                  AND p.polname = 'graph_attack_paths_tenant_isolation'
            ) THEN
                CREATE POLICY graph_attack_paths_tenant_isolation ON graph_attack_paths
                    USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant())
                    WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_app') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE ON graph_attack_paths TO agent_bom_app;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_rls_maintenance') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE ON graph_attack_paths TO agent_bom_rls_maintenance;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_readonly') THEN
                GRANT SELECT ON graph_attack_paths TO agent_bom_readonly;
            END IF;
        END
        $$
    """)
    op.execute("""
        UPDATE control_plane_schema_versions SET version=7,updated_at=now()
        WHERE component='graph' AND version=6
    """)


def downgrade() -> None:
    # Older runtimes ignore the table and derive on read; dropping it only
    # discards a recomputable index.
    op.execute("DROP TABLE IF EXISTS graph_attack_paths")
    op.execute("UPDATE control_plane_schema_versions SET version=6,updated_at=now() WHERE component='graph' AND version=7")
