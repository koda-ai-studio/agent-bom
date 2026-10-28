"""Store the normalized blueprint key so restricted RLS queries can seek it.

Adding a stored generated column rewrites ``drift_incidents`` under an
ACCESS EXCLUSIVE lock for the duration of the rewrite; gateway and API
writers to that table block until it commits. The partial index is then built
``CONCURRENTLY`` outside the migration transaction, so the lock is held only
for the column rewrite, not for the index build. Schedule this migration before
starting new API/gateway replicas; older writers remain compatible because
PostgreSQL computes the key from their existing JSON writes.

The column and index DDL must match ``DRIFT_BLUEPRINT_KEY_COLUMN_DDL`` and
``DRIFT_BLUEPRINT_OPEN_INDEX_DDL`` in ``agent_bom.api.storage.registry_schema``
(modulo ``CONCURRENTLY``), or the planner ignores the index.
"""

from alembic import op

revision = "20261027_03"
down_revision = "20261027_02"
branch_labels = None
depends_on = None


def _table_exists() -> bool:
    return op.get_bind().exec_driver_sql("SELECT to_regclass('public.drift_incidents')").scalar() is not None


def _index_is_invalid(name: str) -> bool:
    return bool(
        op.get_bind()
        .exec_driver_sql(
            "SELECT NOT i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid "
            "JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=%(name)s",
            {"name": name},
        )
        .scalar()
    )


def upgrade() -> None:
    if not _table_exists():
        return
    op.execute(r"""
ALTER TABLE public.drift_incidents ADD COLUMN IF NOT EXISTS blueprint_key TEXT
 GENERATED ALWAYS AS (lower(replace(btrim(data->>'blueprint_id', E' \t\n\x0b\f\r'), '-', '_'))) STORED;
""")
    with op.get_context().autocommit_block():
        # A CONCURRENTLY build that was cancelled or timed out leaves the index
        # INVALID; IF NOT EXISTS would keep it and the planner would ignore it.
        if _index_is_invalid("idx_drift_incidents_tenant_blueprint_key_open"):
            op.execute("DROP INDEX CONCURRENTLY IF EXISTS public.idx_drift_incidents_tenant_blueprint_key_open")
        op.execute(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_drift_incidents_tenant_blueprint_key_open ON public.drift_incidents "
            "(tenant_id, blueprint_key, last_detected_at DESC, incident_id DESC) WHERE NOT resolved"
        )
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS public.idx_drift_incidents_tenant_blueprint_open")
    op.execute("ANALYZE public.drift_incidents")
    op.execute("UPDATE control_plane_schema_versions SET version=GREATEST(version,2),updated_at=now() WHERE component='drift_incidents'")


def downgrade() -> None:
    if not _table_exists():
        return
    with op.get_context().autocommit_block():
        op.execute(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_drift_incidents_tenant_blueprint_open ON public.drift_incidents "
            r"(tenant_id, (lower(replace(btrim(data->>'blueprint_id', E' \t\n\x0b\f\r'), '-', '_'))), last_detected_at DESC) "
            "WHERE NOT resolved"
        )
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS public.idx_drift_incidents_tenant_blueprint_key_open")
    op.execute("ALTER TABLE public.drift_incidents DROP COLUMN IF EXISTS blueprint_key")
    op.execute("UPDATE control_plane_schema_versions SET version=1,updated_at=now() WHERE component='drift_incidents'")
