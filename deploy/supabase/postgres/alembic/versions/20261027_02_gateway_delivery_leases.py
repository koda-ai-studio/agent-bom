"""Shared gateway audit delivery with tenant RLS and fenced leases."""

from alembic import op

revision = "20261027_02"
down_revision = "20261027_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
CREATE TABLE IF NOT EXISTS gateway_audit_outbox (
    tenant_id TEXT NOT NULL,
    stream_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    digest TEXT NOT NULL,
    payload TEXT NOT NULL,
    payload_bytes INTEGER NOT NULL CHECK (payload_bytes > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    lease_token TEXT,
    lease_until TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, stream_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_gateway_audit_outbox_claim
    ON gateway_audit_outbox(tenant_id, stream_id, created_at, event_id);

ALTER TABLE gateway_audit_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateway_audit_outbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS gateway_audit_outbox_tenant_isolation ON gateway_audit_outbox;
CREATE POLICY gateway_audit_outbox_tenant_isolation ON gateway_audit_outbox
 USING (public.abom_rls_bypass() OR tenant_id=public.abom_current_tenant())
 WITH CHECK (public.abom_rls_bypass() OR tenant_id=public.abom_current_tenant());
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='agent_bom_app') THEN
  GRANT SELECT,INSERT,UPDATE,DELETE ON gateway_audit_outbox TO agent_bom_app;
 END IF;
 -- Evidence reviewers read the queue; init.sql's default privileges belong to
 -- the bootstrap owner and do not reach tables a different migration role
 -- creates. The cross-tenant RLS maintenance role has no consumer here, so it
 -- gets no DML on queued audit evidence.
 IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='agent_bom_readonly') THEN
  GRANT SELECT ON gateway_audit_outbox TO agent_bom_readonly;
 END IF;
END $$;
INSERT INTO control_plane_schema_versions(component,version,updated_at) VALUES ('gateway_audit_outbox',1,now())
ON CONFLICT(component) DO NOTHING;
""")


def downgrade() -> None:
    raise RuntimeError("Drain shared gateway audit delivery before a manual downgrade; queued evidence must be preserved")
