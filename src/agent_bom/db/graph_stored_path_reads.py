"""Reads of a snapshot's stored attack-path index, shared by the SQLite and Postgres stores.

Scan snapshots keep their paths only in ``graph_attack_paths``, the ranked index
``GET /v1/graph/attack-paths`` serves; the legacy ``attack_paths`` table is
filled only by graphs saved with in-memory paths. Every per-snapshot path read
answers from the index when it matches this runtime's derivation, so paging,
per-source reads, impact depth and the delta digest count the same paths as the
queue. Each function returns ``None`` when the caller should keep reading the
legacy table. Every statement filters on ``(tenant_id, scan_id)``.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from agent_bom.graph.path_records import AttackPath
from agent_bom.graph.snapshot_paths import path_from_json, stored_paths_current


def _status(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    try:
        value = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def stored_index_current(conn: Any, *, tenant_id: str, scan_id: str, ph: str) -> bool:
    """Whether the snapshot's stored paths are complete for this runtime's derivation."""
    row = conn.execute(
        f"SELECT analysis_status FROM graph_snapshots WHERE tenant_id = {ph} AND scan_id = {ph}",  # nosec B608 - placeholder only
        (tenant_id, scan_id),
    ).fetchone()
    return row is not None and stored_paths_current(_status(row[0]))


def stored_paths_page(conn: Any, *, tenant_id: str, scan_id: str, offset: int, limit: int, ph: str) -> tuple[list[AttackPath], int] | None:
    """One page of stored paths in rank order with the snapshot total; ``None`` without a current index."""
    if not stored_index_current(conn, tenant_id=tenant_id, scan_id=scan_id, ph=ph):
        return None
    scope = f"FROM graph_attack_paths WHERE tenant_id = {ph} AND scan_id = {ph}"
    total = conn.execute(f"SELECT COUNT(*) {scope}", (tenant_id, scan_id)).fetchone()[0]  # nosec B608 - static scope
    rows = conn.execute(
        f"SELECT path_json {scope} ORDER BY rank_index LIMIT {ph} OFFSET {ph}",  # nosec B608 - static scope
        (tenant_id, scan_id, limit, offset),
    ).fetchall()
    return [path_from_json(row[0]) for row in rows], int(total or 0)


def stored_paths_for_sources(conn: Any, *, tenant_id: str, scan_id: str, source_ids: Iterable[str], ph: str) -> list[AttackPath] | None:
    """Stored paths starting at ``source_ids``, in rank order; ``None`` without a current index."""
    if not stored_index_current(conn, tenant_id=tenant_id, scan_id=scan_id, ph=ph):
        return None
    sources = sorted(source_ids)
    if not sources:
        return []
    rows = conn.execute(
        f"SELECT path_json FROM graph_attack_paths WHERE tenant_id = {ph} AND scan_id = {ph} "  # nosec B608 - placeholders only
        f"AND source_node IN ({','.join(ph for _ in sources)}) ORDER BY rank_index",
        (tenant_id, scan_id, *sources),
    ).fetchall()
    return [path_from_json(row[0]) for row in rows]


def stored_longest_path_to(conn: Any, *, tenant_id: str, scan_id: str, node_id: str, ph: str) -> int | None:
    """Edges on the longest stored path ending at ``node_id``; ``None`` without a current index."""
    if not stored_index_current(conn, tenant_id=tenant_id, scan_id=scan_id, ph=ph):
        return None
    row = conn.execute(
        f"SELECT MAX(hop_count) FROM graph_attack_paths WHERE tenant_id = {ph} AND scan_id = {ph} AND target_node = {ph}",  # nosec B608
        (tenant_id, scan_id, node_id),
    ).fetchone()
    return int(row[0] or 0) if row else 0


def stored_path_endpoints(conn: Any, *, tenant_id: str, scan_id: str, ph: str) -> list[tuple[str, str]] | None:
    """``(source, target)`` of every stored path, for the prior-snapshot delta digest; ``None`` when none are stored.

    Not gated on the derivation version: an endpoint pair is stable across
    derivation changes, and a stale index still says which routes existed.
    """
    rows = conn.execute(
        f"SELECT source_node, target_node FROM graph_attack_paths WHERE tenant_id = {ph} AND scan_id = {ph}",  # nosec B608
        (tenant_id, scan_id),
    ).fetchall()
    return [(str(row[0]), str(row[1])) for row in rows] if rows else None


__all__ = [
    "stored_index_current",
    "stored_longest_path_to",
    "stored_path_endpoints",
    "stored_paths_for_sources",
    "stored_paths_page",
]
