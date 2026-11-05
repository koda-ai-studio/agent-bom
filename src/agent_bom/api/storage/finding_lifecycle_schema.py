"""Durable per-finding lifecycle, written in the same transaction as the scan that caused it."""

_POSTGRES_TABLE = """CREATE TABLE IF NOT EXISTS finding_lifecycle (
        tenant_id TEXT NOT NULL,
        scope_hash TEXT NOT NULL,
        finding_key TEXT NOT NULL,
        canonical_id TEXT NOT NULL,
        report_canonical_id TEXT,
        environment TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL,
        first_seen TEXT COLLATE "C" NOT NULL,
        last_seen TEXT COLLATE "C" NOT NULL,
        resolved_at TEXT COLLATE "C",
        resolution_reason TEXT,
        reopened_at TEXT COLLATE "C",
        scan_count INTEGER NOT NULL,
        last_job_id TEXT NOT NULL,
        unconfirmed_job_id TEXT,
        unconfirmed_at TEXT COLLATE "C",
        asset_key TEXT,
        coverage_key TEXT,
        payload_hash TEXT NOT NULL,
        payload TEXT NOT NULL,
        PRIMARY KEY (tenant_id, scope_hash, finding_key))"""

_SQLITE_TABLE = """CREATE TABLE IF NOT EXISTS finding_lifecycle (
        tenant_id TEXT NOT NULL,
        scope_hash TEXT NOT NULL,
        finding_key TEXT NOT NULL,
        canonical_id TEXT NOT NULL,
        report_canonical_id TEXT,
        environment TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        resolved_at TEXT,
        resolution_reason TEXT,
        reopened_at TEXT,
        scan_count INTEGER NOT NULL,
        last_job_id TEXT NOT NULL,
        unconfirmed_job_id TEXT,
        unconfirmed_at TEXT,
        asset_key TEXT,
        coverage_key TEXT,
        payload_hash TEXT NOT NULL,
        payload TEXT NOT NULL,
        PRIMARY KEY (tenant_id, scope_hash, finding_key))"""

_LIFECYCLE_DDL = (
    """CREATE INDEX IF NOT EXISTS idx_finding_lifecycle_scope_status
        ON finding_lifecycle (tenant_id, scope_hash, status, finding_key)""",
    """CREATE INDEX IF NOT EXISTS idx_finding_lifecycle_live
        ON finding_lifecycle (tenant_id, last_seen, canonical_id) WHERE status <> 'resolved'""",
    """CREATE INDEX IF NOT EXISTS idx_finding_lifecycle_resolved
        ON finding_lifecycle (tenant_id, resolved_at DESC, canonical_id) WHERE status = 'resolved'""",
    """CREATE INDEX IF NOT EXISTS idx_finding_lifecycle_last_job
        ON finding_lifecycle (tenant_id, last_job_id)""",
    """CREATE TABLE IF NOT EXISTS finding_lifecycle_scans (
        tenant_id TEXT NOT NULL,
        scope_hash TEXT NOT NULL,
        job_id TEXT NOT NULL,
        evidence_at TEXT {collate} NOT NULL,
        complete INTEGER NOT NULL,
        PRIMARY KEY (tenant_id, scope_hash, job_id))""",
    """CREATE INDEX IF NOT EXISTS idx_finding_lifecycle_scans_time
        ON finding_lifecycle_scans (tenant_id, scope_hash, evidence_at)""",
    """CREATE INDEX IF NOT EXISTS idx_finding_lifecycle_scans_job
        ON finding_lifecycle_scans (tenant_id, job_id)""",
    """CREATE TABLE IF NOT EXISTS finding_lifecycle_backfill (
        tenant_id TEXT NOT NULL PRIMARY KEY,
        version INTEGER NOT NULL)""",
)


def _ddl(table: str, collate: str) -> tuple[str, ...]:
    return (table, *(statement.replace("{collate}", collate) for statement in _LIFECYCLE_DDL))


def initialize_sqlite_finding_lifecycle(conn) -> None:  # type: ignore[no-untyped-def]
    for statement in _ddl(_SQLITE_TABLE, ""):
        conn.execute(statement)


def forget_job_evidence(session, tenant_ids, job_id: str) -> None:  # type: ignore[no-untyped-def]
    """An explicitly deleted scan takes the findings only it ever reported; retention never calls this."""
    for tenant_id in tenant_ids:
        session.execute("DELETE FROM finding_lifecycle WHERE tenant_id=? AND last_job_id=? AND scan_count=1", (tenant_id, job_id))
        session.execute("DELETE FROM finding_lifecycle_scans WHERE tenant_id=? AND job_id=?", (tenant_id, job_id))


_RLS_TABLES = ("finding_lifecycle", "finding_lifecycle_scans", "finding_lifecycle_backfill")

_POSTGRES_RLS = "".join(
    f"""
ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;
ALTER TABLE {table} FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS {table}_tenant_isolation ON {table};
CREATE POLICY {table}_tenant_isolation ON {table}
    USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant())
    WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
"""
    for table in _RLS_TABLES
)

POSTGRES_FINDING_LIFECYCLE_V1 = (
    ";\n".join(_ddl(_POSTGRES_TABLE, 'COLLATE "C"'))  # nosec B608 - immutable DDL literals
    + ";\n"  # nosec B608 - immutable DDL literals
    + _POSTGRES_RLS  # nosec B608 - immutable DDL literals
    + """DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON finding_lifecycle, finding_lifecycle_scans, finding_lifecycle_backfill TO agent_bom_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_rls_maintenance') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON finding_lifecycle, finding_lifecycle_scans, finding_lifecycle_backfill
            TO agent_bom_rls_maintenance;
    END IF;
END $$;
INSERT INTO control_plane_schema_versions(component,version,updated_at) VALUES ('scan_jobs',5,now())
ON CONFLICT(component) DO UPDATE SET version=GREATEST(control_plane_schema_versions.version,5);
"""
)
