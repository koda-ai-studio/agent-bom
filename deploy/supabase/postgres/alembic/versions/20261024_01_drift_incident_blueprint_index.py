"""Index open drift incidents by (tenant, normalized blueprint).

The gateway checks a caller's role blueprint for open drift incidents on every
relayed call. It used to read the tenant's newest 200 open incidents and filter
by blueprint in Python, so a tenant with 200+ open incidents lost enforcement
for every blueprint. The lookup now filters by blueprint in SQL; this partial
expression index keeps that lookup bounded by one blueprint's open incidents.

The key expression must match ``DRIFT_BLUEPRINT_KEY_SQL`` in
``agent_bom.api.storage.registry_schema`` exactly, or the planner ignores it.

Revision ID: 20261024_01
Revises: 20261023_02
"""

from __future__ import annotations

from alembic import op

revision = "20261024_01"
down_revision = "20261023_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    relation = op.get_bind().exec_driver_sql("SELECT to_regclass('public.drift_incidents')").scalar()
    if relation is None:
        return
    with op.get_context().autocommit_block():
        op.execute(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_drift_incidents_tenant_blueprint_open ON public.drift_incidents "
            r"(tenant_id, (lower(replace(btrim(data->>'blueprint_id', E' \t\n\x0b\f\r'), '-', '_'))), last_detected_at DESC) "
            "WHERE NOT resolved"
        )


def downgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS public.idx_drift_incidents_tenant_blueprint_open")
