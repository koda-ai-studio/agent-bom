"""Additive checkpoint and bounded replay-receipt schema; observations stay in runtime storage."""

CHECKPOINT_DDL = """CREATE TABLE IF NOT EXISTS trace_collection_checkpoints (
    tenant_id TEXT NOT NULL, connection_id TEXT NOT NULL, data TEXT NOT NULL,
    PRIMARY KEY (tenant_id, connection_id))"""
RECEIPT_DDL = """CREATE TABLE IF NOT EXISTS trace_collection_receipts (
    tenant_id TEXT NOT NULL, connection_id TEXT NOT NULL, observation_id TEXT NOT NULL,
    observed_at TEXT NOT NULL, digest TEXT NOT NULL,
    PRIMARY KEY (tenant_id, connection_id, observation_id))"""
RECEIPT_INDEX = """CREATE INDEX IF NOT EXISTS idx_trace_collection_receipts_window
    ON trace_collection_receipts(tenant_id, connection_id, observed_at)"""

POSTGRES_TRACE_COLLECTION_V1 = ";\n".join(
    (
        CHECKPOINT_DDL,
        RECEIPT_DDL,
        RECEIPT_INDEX,
        """
ALTER TABLE trace_collection_checkpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE trace_collection_checkpoints FORCE ROW LEVEL SECURITY;
ALTER TABLE trace_collection_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE trace_collection_receipts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS trace_collection_checkpoints_tenant_isolation ON trace_collection_checkpoints;
CREATE POLICY trace_collection_checkpoints_tenant_isolation ON trace_collection_checkpoints
    USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant())
    WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
DROP POLICY IF EXISTS trace_collection_receipts_tenant_isolation ON trace_collection_receipts;
CREATE POLICY trace_collection_receipts_tenant_isolation ON trace_collection_receipts
    USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant())
    WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON trace_collection_checkpoints, trace_collection_receipts TO agent_bom_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_rls_maintenance') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON trace_collection_checkpoints, trace_collection_receipts TO agent_bom_rls_maintenance;
    END IF;
END $$;
INSERT INTO control_plane_schema_versions(component,version,updated_at) VALUES ('trace_collection',1,now())
ON CONFLICT(component) DO NOTHING;
""",
    )
)
