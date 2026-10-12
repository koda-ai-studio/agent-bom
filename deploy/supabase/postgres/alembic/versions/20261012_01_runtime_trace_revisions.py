"""Retain native span revisions separately from their current projection."""

from alembic import op

revision = "20261012_01"
down_revision = "20261011_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS runtime_observation_revisions (
            tenant_id TEXT NOT NULL,
            observation_id TEXT NOT NULL,
            revision INTEGER NOT NULL,
            content_hash TEXT NOT NULL,
            data TEXT NOT NULL,
            PRIMARY KEY (tenant_id, observation_id, revision),
            UNIQUE (tenant_id, observation_id, content_hash)
        )
    """)
    op.execute("ALTER TABLE runtime_observation_revisions ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE runtime_observation_revisions FORCE ROW LEVEL SECURITY")
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_policy p
                WHERE p.polrelid = to_regclass('runtime_observation_revisions')
                  AND p.polname = 'runtime_observation_revisions_tenant_isolation'
            ) THEN
                CREATE POLICY runtime_observation_revisions_tenant_isolation ON runtime_observation_revisions
                    USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant())
                    WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_app') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE ON runtime_observation_revisions TO agent_bom_app;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_rls_maintenance') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE ON runtime_observation_revisions TO agent_bom_rls_maintenance;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_readonly') THEN
                GRANT SELECT ON runtime_observation_revisions TO agent_bom_readonly;
            END IF;
        END
        $$
    """)
    op.execute("""
        INSERT INTO control_plane_schema_versions(component,version,updated_at)
        VALUES ('runtime_events',4,now())
        ON CONFLICT (component) DO UPDATE SET version=GREATEST(control_plane_schema_versions.version,4),updated_at=now()
    """)


def downgrade() -> None:
    raise NotImplementedError("Retain imported evidence and resume state; restore a reviewed backup for rollback")
