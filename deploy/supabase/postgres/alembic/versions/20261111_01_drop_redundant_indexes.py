"""Drop indexes that no application query can use.

Each one is maintained on every push and never read:

* ``idx_pg_graph_node_search_lower_trgm`` is a trigram GIN index on
  ``LOWER(search_text)``. ``search_text`` is stored lowercased and graph search
  filters ``search_text LIKE``, so this expression index never matches. It was
  as large as the trigram index that search does use (77 MB each at four
  200-agent tenants).
* ``idx_pg_graph_nodes_entity_type`` indexes ``entity_type`` alone on a tenant
  table. Every ``graph_nodes`` read filters ``tenant_id`` and ``scan_id`` first.
* ``idx_jobs_team_created``, ``idx_jobs_batch``, ``idx_jobs_parent`` and
  ``idx_jobs_schedule`` duplicate ``idx_pg_jobs_*`` column for column.

Revision ID: 20261111_01
Revises: 20261106_01
"""

from __future__ import annotations

from alembic import op

revision = "20261111_01"
down_revision = "20261106_01"
branch_labels = None
depends_on = None

_TABLES = ("graph_node_search", "graph_nodes", "scan_jobs")


def upgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS public.idx_pg_graph_node_search_lower_trgm")
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS public.idx_pg_graph_nodes_entity_type")
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS public.idx_jobs_team_created")
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS public.idx_jobs_batch")
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS public.idx_jobs_parent")
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS public.idx_jobs_schedule")


def downgrade() -> None:
    bind = op.get_bind()
    present = {table for table in _TABLES if bind.exec_driver_sql(f"SELECT to_regclass('public.{table}')").scalar()}
    with op.get_context().autocommit_block():
        if "graph_node_search" in present:
            op.execute(
                "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_pg_graph_node_search_lower_trgm ON public.graph_node_search "
                "USING gin (LOWER(search_text) gin_trgm_ops)"
            )
        if "graph_nodes" in present:
            op.execute("CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_pg_graph_nodes_entity_type ON public.graph_nodes (entity_type)")
        if "scan_jobs" in present:
            op.execute("CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_jobs_team_created ON public.scan_jobs (team_id, created_at DESC)")
            op.execute("CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_jobs_batch ON public.scan_jobs (team_id, batch_id, created_at DESC)")
            op.execute(
                "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_jobs_parent ON public.scan_jobs (team_id, parent_job_id, created_at DESC)"
            )
            op.execute(
                "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_jobs_schedule ON public.scan_jobs (team_id, schedule_id, created_at DESC)"
            )
