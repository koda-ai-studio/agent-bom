"""Let the DML-only app role refresh graph planner statistics after a large save.

Right after a large snapshot save ``graph_nodes`` and ``graph_edges`` have no
planner statistics until autovacuum reaches them, and the explicit-scan graph
reads plan without them (measured at 5,000 agents: 586 ms median before
``ANALYZE``, 166 ms after). The app role cannot run ``ANALYZE`` on tables it
does not own, and it must not gain ownership or a general maintenance grant.

``public.abom_analyze_graph_tables()`` is the narrow grant instead:

* ``SECURITY DEFINER``, owned by the role that runs this migration (the schema
  owner), with ``search_path`` pinned to ``pg_catalog, pg_temp``;
* no arguments and no dynamic SQL: it analyzes exactly ``public.graph_nodes``
  and ``public.graph_edges`` and nothing else;
* a transaction-scoped advisory lock and a 60-second cool-down per table, so
  repeated calls cannot queue ``ANALYZE`` work: a call that loses the lock, or
  finds both tables analyzed within the cool-down, does nothing;
* ``EXECUTE`` revoked from ``PUBLIC`` and granted only to ``agent_bom_app``.

It returns how many tables it analyzed (0, 1 or 2).

Revision ID: 20261114_01
Revises: 20261113_01
"""

from __future__ import annotations

from alembic import op

revision = "20261114_01"
down_revision = "20261113_01"
branch_labels = None
depends_on = None

ANALYZE_FUNCTION_SQL = """
CREATE OR REPLACE FUNCTION public.abom_analyze_graph_tables()
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $analyze$
DECLARE
  v_analyzed INTEGER := 0;
  v_recent TIMESTAMPTZ;
BEGIN
  -- One caller at a time; a concurrent call returns at once instead of queueing.
  IF NOT pg_try_advisory_xact_lock(hashtext('agent_bom.analyze_graph_tables')) THEN
    RETURN 0;
  END IF;
  SELECT greatest(last_analyze, last_autoanalyze) INTO v_recent
    FROM pg_stat_user_tables WHERE relid = 'public.graph_nodes'::regclass;
  IF v_recent IS NULL OR v_recent < clock_timestamp() - interval '60 seconds' THEN
    ANALYZE public.graph_nodes;
    v_analyzed := v_analyzed + 1;
  END IF;
  SELECT greatest(last_analyze, last_autoanalyze) INTO v_recent
    FROM pg_stat_user_tables WHERE relid = 'public.graph_edges'::regclass;
  IF v_recent IS NULL OR v_recent < clock_timestamp() - interval '60 seconds' THEN
    ANALYZE public.graph_edges;
    v_analyzed := v_analyzed + 1;
  END IF;
  RETURN v_analyzed;
END
$analyze$;

REVOKE ALL ON FUNCTION public.abom_analyze_graph_tables() FROM PUBLIC;

DO $analyze_roles$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_app') THEN
    GRANT EXECUTE ON FUNCTION public.abom_analyze_graph_tables() TO agent_bom_app;
  END IF;
END
$analyze_roles$;
"""


def upgrade() -> None:
    tables = "SELECT to_regclass('public.graph_nodes') IS NOT NULL AND to_regclass('public.graph_edges') IS NOT NULL"
    if not op.get_bind().exec_driver_sql(tables).scalar():
        return
    op.execute(ANALYZE_FUNCTION_SQL)


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS public.abom_analyze_graph_tables()")
