"""Advisory AI assessments and per-scan AI run status, tenant-scoped.

Empty tables only, so the upgrade is brief. Nothing outside the AI advice surfaces
reads them, and replicas on the previous release ignore them.

Revision ID: 20261105_04
Revises: 20261105_03
"""

from __future__ import annotations

from alembic import op

revision = "20261105_04"
down_revision = "20261105_03"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS ai_finding_assessments (
            tenant_id TEXT NOT NULL CHECK (length(btrim(tenant_id)) > 0),
            scan_id TEXT NOT NULL,
            finding_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            data JSONB NOT NULL,
            PRIMARY KEY (tenant_id, scan_id, finding_id)
        );
        CREATE INDEX IF NOT EXISTS idx_ai_finding_assessments_latest ON public.ai_finding_assessments (tenant_id, finding_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_ai_finding_assessments_created ON public.ai_finding_assessments (created_at);
        ALTER TABLE public.ai_finding_assessments ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.ai_finding_assessments FORCE ROW LEVEL SECURITY;
        DROP POLICY IF EXISTS ai_finding_assessments_tenant_isolation ON public.ai_finding_assessments;
        CREATE POLICY ai_finding_assessments_tenant_isolation ON public.ai_finding_assessments USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant()) WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
        GRANT SELECT, INSERT, UPDATE, DELETE ON public.ai_finding_assessments TO agent_bom_app, agent_bom_rls_maintenance;
        CREATE TABLE IF NOT EXISTS ai_triage_runs (
            tenant_id TEXT NOT NULL CHECK (length(btrim(tenant_id)) > 0),
            scan_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            data JSONB NOT NULL,
            PRIMARY KEY (tenant_id, scan_id)
        );
        CREATE INDEX IF NOT EXISTS idx_ai_triage_runs_latest ON public.ai_triage_runs (tenant_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_ai_triage_runs_created ON public.ai_triage_runs (created_at);
        ALTER TABLE public.ai_triage_runs ENABLE ROW LEVEL SECURITY;
        ALTER TABLE public.ai_triage_runs FORCE ROW LEVEL SECURITY;
        DROP POLICY IF EXISTS ai_triage_runs_tenant_isolation ON public.ai_triage_runs;
        CREATE POLICY ai_triage_runs_tenant_isolation ON public.ai_triage_runs USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant()) WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
        GRANT SELECT, INSERT, UPDATE, DELETE ON public.ai_triage_runs TO agent_bom_app, agent_bom_rls_maintenance;
        INSERT INTO control_plane_schema_versions(component,version,updated_at) VALUES ('ai_triage',1,now()) ON CONFLICT(component) DO UPDATE SET version=GREATEST(control_plane_schema_versions.version,1);
        """
    )


def downgrade() -> None:
    op.execute(
        "DROP TABLE IF EXISTS public.ai_finding_assessments; DROP TABLE IF EXISTS public.ai_triage_runs; DELETE FROM control_plane_schema_versions WHERE component='ai_triage'"
    )
