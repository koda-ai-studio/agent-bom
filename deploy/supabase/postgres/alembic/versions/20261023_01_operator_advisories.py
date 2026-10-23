"""Persist operator-declared advisories and their re-match cursor per tenant.

Operators declare an advisory before feeds publish it; matching reads stored
inventory. The re-match state row holds the tenant's cursor and last-run
status so a daily job advances only after a complete run.

Revision ID: 20261023_01
Revises: 20261022_01
"""

from alembic import op

revision = "20261023_01"
down_revision = "20261022_01"
branch_labels = None
depends_on = None

_TABLES = ("operator_advisories", "operator_advisory_rematch_state")


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS operator_advisories (
            tenant_id TEXT NOT NULL,
            advisory_id TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            data TEXT NOT NULL,
            PRIMARY KEY (tenant_id, advisory_id)
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_operator_advisories_updated ON operator_advisories(tenant_id, updated_at)")
    op.execute("""
        CREATE TABLE IF NOT EXISTS operator_advisory_rematch_state (
            tenant_id TEXT PRIMARY KEY,
            updated_at TEXT NOT NULL,
            data TEXT NOT NULL
        )
    """)
    for table in _TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(f"""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_policy p
                    WHERE p.polrelid = to_regclass('{table}') AND p.polname = '{table}_tenant_isolation'
                ) THEN
                    CREATE POLICY {table}_tenant_isolation ON {table}
                        USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant())
                        WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
                END IF;
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_app') THEN
                    GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO agent_bom_app;
                END IF;
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_rls_maintenance') THEN
                    GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO agent_bom_rls_maintenance;
                END IF;
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_readonly') THEN
                    GRANT SELECT ON {table} TO agent_bom_readonly;
                END IF;
            END
            $$
        """)
    op.execute("""
        INSERT INTO control_plane_schema_versions(component, version, updated_at)
        VALUES ('operator_advisories', 1, now())
        ON CONFLICT(component) DO UPDATE SET version = GREATEST(control_plane_schema_versions.version, excluded.version),
            updated_at = excluded.updated_at
    """)


def downgrade() -> None:
    # Older runtimes neither read nor write these tables; dropping them loses
    # only operator-declared advisories and the re-match cursor.
    op.execute("DELETE FROM control_plane_schema_versions WHERE component = 'operator_advisories'")
    op.execute("DROP TABLE IF EXISTS operator_advisory_rematch_state")
    op.execute("DROP TABLE IF EXISTS operator_advisories")
