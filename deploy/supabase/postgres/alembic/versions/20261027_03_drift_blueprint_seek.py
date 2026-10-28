"""Store the normalized blueprint key so restricted RLS queries can seek it.

Adding a stored generated column rewrites the table under a write lock. Schedule
this migration before starting new API/gateway replicas; older writers remain
compatible because PostgreSQL computes the key from their existing JSON writes.
"""

from alembic import op

revision = "20261027_03"
down_revision = "20261027_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(r"""
ALTER TABLE public.drift_incidents ADD COLUMN IF NOT EXISTS blueprint_key TEXT
 GENERATED ALWAYS AS (lower(replace(btrim(data->>'blueprint_id', E' \t\n\x0b\f\r'), '-', '_'))) STORED;
CREATE INDEX IF NOT EXISTS idx_drift_incidents_tenant_blueprint_key_open
 ON public.drift_incidents (tenant_id, blueprint_key, last_detected_at DESC, incident_id DESC) WHERE NOT resolved;
DROP INDEX IF EXISTS public.idx_drift_incidents_tenant_blueprint_open;
ANALYZE public.drift_incidents;
UPDATE control_plane_schema_versions SET version=GREATEST(version,2),updated_at=now() WHERE component='drift_incidents';
""")


def downgrade() -> None:
    op.execute(r"""
CREATE INDEX IF NOT EXISTS idx_drift_incidents_tenant_blueprint_open ON public.drift_incidents
 (tenant_id, (lower(replace(btrim(data->>'blueprint_id', E' \t\n\x0b\f\r'), '-', '_'))), last_detected_at DESC) WHERE NOT resolved;
DROP INDEX IF EXISTS public.idx_drift_incidents_tenant_blueprint_key_open;
ALTER TABLE public.drift_incidents DROP COLUMN IF EXISTS blueprint_key;
UPDATE control_plane_schema_versions SET version=1,updated_at=now() WHERE component='drift_incidents';
""")
