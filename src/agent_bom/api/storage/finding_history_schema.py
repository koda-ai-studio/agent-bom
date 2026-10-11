"""Immutable v1 DDL for atomic, disposable finding-history projections."""

HISTORY_DDL = (
    """CREATE TABLE IF NOT EXISTS finding_history_jobs (
        tenant_id TEXT NOT NULL, job_id TEXT NOT NULL, version INTEGER NOT NULL,
        metadata TEXT NOT NULL, PRIMARY KEY (tenant_id, job_id))""",
    """CREATE TABLE IF NOT EXISTS finding_history_rows (
        tenant_id TEXT NOT NULL, job_id TEXT NOT NULL, ordinal INTEGER NOT NULL,
        history_key TEXT NOT NULL, evidence_at TEXT NOT NULL, completed_at TEXT NOT NULL, payload TEXT NOT NULL,
        PRIMARY KEY (tenant_id, job_id, ordinal))""",
    """CREATE INDEX IF NOT EXISTS idx_finding_history_identity
        ON finding_history_rows (tenant_id, history_key, job_id, ordinal)""",
)


def initialize_sqlite_finding_history(conn):
    """Install invalidation in the same schema transaction as the job store."""
    for statement in HISTORY_DDL:
        conn.execute(statement)
    for event in ("INSERT", "UPDATE", "DELETE"):
        references = ("OLD", "NEW") if event == "UPDATE" else ("OLD",) if event == "DELETE" else ("NEW",)
        statements = " ".join(
            f"DELETE FROM {table} WHERE tenant_id={ref}.tenant_id AND job_id={ref}.job_id;"  # nosec B608 - fixed trigger identifiers
            for ref in references
            for table in ("finding_history_rows", "finding_history_jobs")
        )
        conn.execute(f"CREATE TRIGGER IF NOT EXISTS finding_history_{event.lower()} AFTER {event} ON jobs BEGIN {statements} END")


POSTGRES_FINDING_HISTORY_V1 = (
    ";\n".join(HISTORY_DDL)  # nosec B608 - immutable DDL literals
    + ";\n"  # nosec B608 - immutable DDL literals
    + """
ALTER TABLE finding_history_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_history_jobs FORCE ROW LEVEL SECURITY;
ALTER TABLE finding_history_rows ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_history_rows FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS finding_history_jobs_tenant_isolation ON finding_history_jobs;
CREATE POLICY finding_history_jobs_tenant_isolation ON finding_history_jobs
    USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant())
    WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
DROP POLICY IF EXISTS finding_history_rows_tenant_isolation ON finding_history_rows;
CREATE POLICY finding_history_rows_tenant_isolation ON finding_history_rows
    USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant())
    WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
CREATE OR REPLACE FUNCTION public.abom_invalidate_finding_history() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        DELETE FROM public.finding_history_rows WHERE tenant_id=OLD.team_id AND job_id=OLD.job_id;
        DELETE FROM public.finding_history_jobs WHERE tenant_id=OLD.team_id AND job_id=OLD.job_id;
    END IF;
    IF TG_OP <> 'DELETE' THEN
        DELETE FROM public.finding_history_rows WHERE tenant_id=NEW.team_id AND job_id=NEW.job_id;
        DELETE FROM public.finding_history_jobs WHERE tenant_id=NEW.team_id AND job_id=NEW.job_id;
    END IF;
    RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS scan_jobs_finding_history ON public.scan_jobs;
CREATE TRIGGER scan_jobs_finding_history AFTER INSERT OR UPDATE OR DELETE ON public.scan_jobs
    FOR EACH ROW EXECUTE FUNCTION public.abom_invalidate_finding_history();
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON finding_history_jobs, finding_history_rows TO agent_bom_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_rls_maintenance') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON finding_history_jobs, finding_history_rows TO agent_bom_rls_maintenance;
    END IF;
END $$;
"""
)

POSTGRES_FINDING_HISTORY_V1 += """
INSERT INTO control_plane_schema_versions(component,version,updated_at) VALUES ('scan_jobs',4,now())
ON CONFLICT(component) DO UPDATE SET version=GREATEST(control_plane_schema_versions.version,4);
"""
