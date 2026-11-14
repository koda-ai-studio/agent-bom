"""Drop graph_edges indexes that only repeat another index's leading columns.

* ``idx_pg_graph_edges_scan`` is ``(tenant_id, scan_id)``, the leading columns
  of ``idx_pg_graph_edges_snapshot_key``.
* ``idx_pg_graph_edges_scan_source`` is ``(tenant_id, scan_id, source_id)``,
  also a leading prefix of ``idx_pg_graph_edges_snapshot_key`` in the same
  collation.

Both were maintained on every snapshot write. ``idx_pg_graph_edges_scan_target``
stays: the only index led by ``target_id`` is ``idx_pg_adjacency_in``, whose
``COLLATE "C"`` columns cannot serve a default-collation comparison.

Revision ID: 20261113_01
Revises: 20261112_01
"""

from __future__ import annotations

from alembic import op

revision = "20261113_01"
down_revision = "20261112_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS public.idx_pg_graph_edges_scan")
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS public.idx_pg_graph_edges_scan_source")


def downgrade() -> None:
    if not op.get_bind().exec_driver_sql("SELECT to_regclass('public.graph_edges')").scalar():
        return
    with op.get_context().autocommit_block():
        op.execute("CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_pg_graph_edges_scan ON public.graph_edges (tenant_id, scan_id)")
        op.execute(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_pg_graph_edges_scan_source ON public.graph_edges (tenant_id, scan_id, source_id)"
        )
