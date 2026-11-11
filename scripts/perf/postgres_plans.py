"""Review ``EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)`` output for the hot reads.

A plan is flagged when it reads a tenant-scoped table sequentially past a row
threshold, or reaches it through an index whose leading column is not
the tenant column. A primary-key lookup on a globally unique id is a point read and
is noted rather than flagged.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Any

SEQ_SCAN_MIN_ROWS = 1000
# ``scan_jobs`` and a few older tables carry the tenant as ``team_id``.
TENANT_COLUMNS = frozenset({"tenant_id", "team_id"})
_INDEX_NODES = {"Index Scan", "Index Only Scan", "Bitmap Index Scan"}

INDEX_METADATA_SQL = """
SELECT ic.relname AS index_name,
       tc.relname AS table_name,
       pg_get_indexdef(i.indexrelid, 1, true) AS leading_key,
       i.indisprimary AS is_primary
FROM pg_index i
JOIN pg_class ic ON ic.oid = i.indexrelid
JOIN pg_class tc ON tc.oid = i.indrelid
JOIN pg_namespace n ON n.oid = tc.relnamespace
WHERE n.nspname = 'public'
""".strip()

TENANT_TABLES_SQL = """
SELECT c.table_name
FROM information_schema.columns c
JOIN information_schema.tables t ON t.table_schema = c.table_schema AND t.table_name = c.table_name
WHERE c.table_schema = 'public' AND c.column_name IN ('tenant_id', 'team_id') AND t.table_type = 'BASE TABLE'
""".strip()


def plan_nodes(plan: Mapping[str, Any]) -> Iterator[Mapping[str, Any]]:
    """Depth-first walk of one plan tree, root first."""
    yield plan
    for child in plan.get("Plans") or ():
        yield from plan_nodes(child)


def _examined(node: Mapping[str, Any]) -> int:
    per_loop = int(node.get("Actual Rows") or 0) + int(node.get("Rows Removed by Filter") or 0)
    return per_loop * int(node.get("Actual Loops") or 1)


def review_plan(
    document: list[dict[str, Any]],
    *,
    tenant_tables: frozenset[str] | set[str],
    indexes: Mapping[str, Mapping[str, Any]],
    seq_scan_min_rows: int = SEQ_SCAN_MIN_ROWS,
) -> dict[str, Any]:
    """Summarize one EXPLAIN document: timings, buffers, every scan, and flags."""
    root = document[0]
    plan = root["Plan"]
    flags: list[str] = []
    notes: list[str] = []
    scans: list[dict[str, Any]] = []
    for node in plan_nodes(plan):
        kind = node.get("Node Type", "")
        index = node.get("Index Name")
        meta = indexes.get(index or "", {})
        relation = node.get("Relation Name") or meta.get("table")
        if kind == "Seq Scan" or kind in _INDEX_NODES:
            scans.append({"node": kind, "relation": relation, "index": index, "rows": int(node.get("Actual Rows") or 0)})
        if relation not in tenant_tables:
            continue
        if kind == "Seq Scan" and _examined(node) >= seq_scan_min_rows:
            flags.append(f"seq_scan {relation} examined {_examined(node)} rows")
        elif kind in _INDEX_NODES and meta and meta.get("leading") not in TENANT_COLUMNS:
            if meta.get("primary"):
                notes.append(f"primary-key lookup {index} leads with {meta.get('leading')}")
            else:
                flags.append(f"index {index} on {relation} leads with {meta.get('leading')}, not the tenant column")
    return {
        "execution_ms": root.get("Execution Time"),
        "planning_ms": root.get("Planning Time"),
        "shared_hit_blocks": int(plan.get("Shared Hit Blocks") or 0),
        "shared_read_blocks": int(plan.get("Shared Read Blocks") or 0),
        "scans": scans,
        "flags": flags,
        "notes": notes,
    }
