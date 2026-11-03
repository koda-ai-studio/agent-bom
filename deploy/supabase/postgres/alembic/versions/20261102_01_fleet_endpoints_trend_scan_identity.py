"""Bring upgraded databases up to the fleet endpoint and trend scan identity schema.

``fleet_endpoints`` (endpoint fleet evidence) and ``trend_history.scan_id`` with
its ``(team_id, scan_id)`` unique index (retry-safe trend points) were added to
``init.sql`` / ``runtime-schema.sql`` only. Those files are replayed onto a
database once, by ``20260416_01`` / ``20260718_01``, so a database already past
them never received either change: fleet endpoint writes failed with
``UndefinedTable`` and every trend point failed on its ``ON CONFLICT``.

Every statement is idempotent, so this is a no-op on a database bootstrapped
from the current baseline. ``scan_id`` is added nullable without a default
(catalog-only change), and the partial unique index covers only non-null scan
ids, which an upgraded table does not have yet, so the build is brief.

Revision ID: 20261102_01
Revises: 20261027_03
"""

from alembic import op

revision = "20261102_01"
down_revision = "20261027_03"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS fleet_endpoints (
            tenant_id    TEXT NOT NULL,
            endpoint_id  TEXT NOT NULL,
            completeness TEXT NOT NULL,
            updated_at   TEXT NOT NULL,
            data         JSONB NOT NULL,
            PRIMARY KEY (tenant_id, endpoint_id)
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_fleet_endpoints_tenant_updated ON fleet_endpoints(tenant_id, updated_at DESC, endpoint_id)")
    op.execute("ALTER TABLE fleet_endpoints ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE fleet_endpoints FORCE ROW LEVEL SECURITY")
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_policy p
                WHERE p.polrelid = to_regclass('fleet_endpoints') AND p.polname = 'fleet_endpoints_tenant_isolation'
            ) THEN
                CREATE POLICY fleet_endpoints_tenant_isolation ON fleet_endpoints
                    USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant())
                    WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_app') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE ON fleet_endpoints TO agent_bom_app;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_rls_maintenance') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE ON fleet_endpoints TO agent_bom_rls_maintenance;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_readonly') THEN
                GRANT SELECT ON fleet_endpoints TO agent_bom_readonly;
            END IF;
        END
        $$
    """)
    op.execute("""
        DO $$
        BEGIN
            IF to_regclass('public.trend_history') IS NOT NULL THEN
                ALTER TABLE trend_history ADD COLUMN IF NOT EXISTS scan_id TEXT;
                CREATE UNIQUE INDEX IF NOT EXISTS idx_trend_history_team_scan
                    ON trend_history(team_id, scan_id) WHERE scan_id IS NOT NULL;
            END IF;
        END
        $$
    """)


def downgrade() -> None:
    # Intentionally keeps both: the application at 20261027_03 already reads
    # and writes fleet_endpoints and trend_history.scan_id (they shipped in
    # August), so dropping them would break the version being rolled back to
    # and discard recorded fleet evidence.
    return None
