"""Index shared rate-limit hits by ``hit_at`` for the table-wide prune.

The limiter trims its own bucket on every request through the existing
``(bucket_key, hit_at)`` index. Buckets that never return are removed by a
periodic ``DELETE ... WHERE hit_at < $1``, which cannot use that composite
index and otherwise scans the whole table.

Revision ID: 20261025_01
Revises: 20261024_02
"""

from __future__ import annotations

from alembic import op

revision = "20261025_01"
down_revision = "20261024_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    relation = op.get_bind().exec_driver_sql("SELECT to_regclass('public.api_rate_limit_hits')").scalar()
    if relation is None:
        return
    with op.get_context().autocommit_block():
        op.execute("CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_api_rate_limit_hits_hit_at ON public.api_rate_limit_hits (hit_at)")


def downgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS public.idx_api_rate_limit_hits_hit_at")
