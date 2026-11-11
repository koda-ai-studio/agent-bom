"""``20261111_01`` drops indexes no application query can use; no schema path may recreate them."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POSTGRES_DIR = ROOT / "deploy" / "supabase" / "postgres"
MIGRATION = POSTGRES_DIR / "alembic" / "versions" / "20261111_01_drop_redundant_indexes.py"
DROPPED = (
    # Expression index on LOWER(search_text): search_text is stored lowercased and every
    # search query filters ``gns.search_text LIKE``, so the planner can never match it.
    "idx_pg_graph_node_search_lower_trgm",
    # Global index on a tenant table; every graph_nodes read filters tenant_id and scan_id first.
    "idx_pg_graph_nodes_entity_type",
    # Exact duplicates of idx_pg_jobs_* (same table, columns and order).
    "idx_jobs_team_created",
    "idx_jobs_batch",
    "idx_jobs_parent",
    "idx_jobs_schedule",
)
KEPT = ("idx_pg_jobs_team_created", "idx_pg_jobs_batch", "idx_pg_jobs_parent", "idx_pg_jobs_schedule", "idx_pg_graph_node_search_trgm")


def _source() -> str:
    return MIGRATION.read_text(encoding="utf-8")


def test_migration_chains_from_the_previous_head_and_drops_concurrently() -> None:
    source = _source()
    assert re.search(r'revision\s*=\s*"20261111_01"', source)
    assert re.search(r'down_revision\s*=\s*"20261106_01"', source)
    assert "autocommit_block()" in source
    for name in DROPPED:
        assert f"DROP INDEX CONCURRENTLY IF EXISTS public.{name}" in source


def test_downgrade_restores_every_dropped_index() -> None:
    downgrade = _source().split("def downgrade", 1)[1]
    for name in DROPPED:
        assert re.search(rf"CREATE INDEX CONCURRENTLY IF NOT EXISTS {name} ON public\.\w+", downgrade), name
    assert "USING gin (LOWER(search_text) gin_trgm_ops)" in downgrade


def test_no_bootstrap_or_runtime_schema_recreates_a_dropped_index() -> None:
    sources = {
        "init.sql": (POSTGRES_DIR / "init.sql").read_text(encoding="utf-8"),
        "runtime-schema.sql": (POSTGRES_DIR / "runtime-schema.sql").read_text(encoding="utf-8"),
        "postgres_graph.py": (ROOT / "src/agent_bom/api/postgres_graph.py").read_text(encoding="utf-8"),
        "postgres_graph_schema.py": (ROOT / "src/agent_bom/api/postgres_graph_schema.py").read_text(encoding="utf-8"),
        "postgres_job_store.py": (ROOT / "src/agent_bom/api/postgres_job_store.py").read_text(encoding="utf-8"),
    }
    for label, text in sources.items():
        for name in DROPPED:
            assert not re.search(rf"CREATE INDEX IF NOT EXISTS {name}\b", text), (label, name)
    bootstrap = sources["init.sql"]
    for name in KEPT:
        assert f"CREATE INDEX IF NOT EXISTS {name}" in bootstrap, name


def test_no_application_query_filters_on_lowered_search_text() -> None:
    """The dropped expression index would only serve ``LOWER(search_text)``; nothing issues it."""
    offenders = [
        str(path.relative_to(ROOT))
        for path in (ROOT / "src" / "agent_bom").rglob("*.py")
        if re.search(r"LOWER\(\s*(gns\.)?search_text\s*\)", path.read_text(encoding="utf-8"), re.IGNORECASE)
    ]
    assert offenders == []
