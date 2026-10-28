"""Index tenant-scoped activity time and tie-breaker paging.

Revision ID: 20261027_01
Revises: 20261025_01
"""

from alembic import op

revision = "20261027_01"
down_revision = "20261025_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if op.get_bind().exec_driver_sql("SELECT to_regclass('public.gateway_activity_events')").scalar() is None:
        return
    with op.get_context().autocommit_block():
        op.execute(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_gateway_activity_window "
            "ON public.gateway_activity_events(tenant_id, event_timestamp, event_id)"
        )


def downgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS public.idx_gateway_activity_window")
