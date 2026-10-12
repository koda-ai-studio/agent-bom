"""Atomically checkpoint tenant-scoped native trace import pages."""

from alembic import op

revision = "20261011_01"
down_revision = "20261010_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS runtime_trace_imports (
            tenant_id TEXT NOT NULL,
            import_id TEXT NOT NULL,
            revision INTEGER NOT NULL,
            data TEXT NOT NULL,
            PRIMARY KEY (tenant_id, import_id)
        )
    """)
    op.execute("ALTER TABLE runtime_trace_imports ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE runtime_trace_imports FORCE ROW LEVEL SECURITY")
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_policy p
                WHERE p.polrelid = to_regclass('runtime_trace_imports')
                  AND p.polname = 'runtime_trace_imports_tenant_isolation'
            ) THEN
                CREATE POLICY runtime_trace_imports_tenant_isolation ON runtime_trace_imports
                    USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant())
                    WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_app') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE ON runtime_trace_imports TO agent_bom_app;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_rls_maintenance') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE ON runtime_trace_imports TO agent_bom_rls_maintenance;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_readonly') THEN
                GRANT SELECT ON runtime_trace_imports TO agent_bom_readonly;
            END IF;
        END
        $$
    """)
    op.execute("""
        INSERT INTO control_plane_schema_versions(component,version,updated_at)
        VALUES ('runtime_events',3,now())
        ON CONFLICT (component) DO UPDATE SET version=GREATEST(control_plane_schema_versions.version,3),updated_at=now()
    """)


def downgrade() -> None:
    raise NotImplementedError("Retain imported evidence and resume state; restore a reviewed backup for rollback")
