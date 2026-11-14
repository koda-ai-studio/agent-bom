"""``20261113_01`` drops graph_edges indexes that repeat another index's leading columns; nothing recreates them."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POSTGRES_DIR = ROOT / "deploy" / "supabase" / "postgres"
MIGRATION = POSTGRES_DIR / "alembic" / "versions" / "20261113_01_drop_edge_prefix_indexes.py"
DROPPED = {
    "idx_pg_graph_edges_scan": "(tenant_id, scan_id)",
    "idx_pg_graph_edges_scan_source": "(tenant_id, scan_id, source_id)",
}
# The index whose leading columns, in the default collation, serve every dropped one.
COVERING = "idx_pg_graph_edges_snapshot_key ON graph_edges(tenant_id, scan_id, source_id, target_id, relationship)"


def _source() -> str:
    return MIGRATION.read_text(encoding="utf-8")


def test_migration_chains_from_the_previous_head_and_drops_concurrently() -> None:
    source = _source()
    assert re.search(r'revision\s*=\s*"20261113_01"', source)
    assert re.search(r'down_revision\s*=\s*"20261112_01"', source)
    assert "autocommit_block()" in source
    for name in DROPPED:
        assert f"DROP INDEX CONCURRENTLY IF EXISTS public.{name}" in source


def test_downgrade_restores_every_dropped_index_with_its_columns() -> None:
    downgrade = _source().split("def downgrade", 1)[1]
    for name, columns in DROPPED.items():
        assert f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {name} ON public.graph_edges {columns}" in downgrade, name


def test_the_covering_index_stays_and_no_schema_path_recreates_a_dropped_one() -> None:
    sources = {
        "init.sql": (POSTGRES_DIR / "init.sql").read_text(encoding="utf-8"),
        "postgres_graph_schema.py": (ROOT / "src/agent_bom/api/postgres_graph_schema.py").read_text(encoding="utf-8"),
    }
    for label, text in sources.items():
        for name in DROPPED:
            assert not re.search(rf"CREATE INDEX IF NOT EXISTS {name}\s+ON", text), (label, name)
        assert re.sub(r"\s+", " ", COVERING) in re.sub(r"\s+", " ", text), label
    # The target-led index stays: the only other target-led index uses COLLATE "C".
    assert "idx_pg_graph_edges_scan_target" in sources["postgres_graph_schema.py"]
