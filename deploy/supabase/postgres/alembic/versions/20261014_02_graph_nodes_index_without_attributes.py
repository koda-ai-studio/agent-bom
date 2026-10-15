"""Stop copying graph node attributes into a btree index.

``idx_pg_graph_nodes_scan_id_cover`` carried ``INCLUDE (attributes)``. Btree
leaf tuples cannot hold more than ~2.7 kB, and INCLUDE values are stored
inline (compressed, never TOASTed out of line), so one node with rich evidence
aborted the whole graph snapshot write. The key columns stay indexed; the
attributes are read from the heap row.

Revision ID: 20261014_02
Revises: 20261014_01
"""

from __future__ import annotations

from alembic import op

revision = "20261014_02"
down_revision = "20261014_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    relation = op.get_bind().exec_driver_sql("SELECT to_regclass('public.graph_nodes')").scalar()
    if relation is None:
        return

    with op.get_context().autocommit_block():
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS idx_pg_graph_nodes_scan_id_cover")
        op.execute("CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_pg_graph_nodes_scan_id_cover ON graph_nodes(tenant_id, scan_id, id)")


def downgrade() -> None:
    # Restoring INCLUDE (attributes) fails on any database that already holds a
    # wide node, and the earlier revision reads through the key-only index.
    pass
