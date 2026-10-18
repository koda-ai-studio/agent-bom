"""SQLite persistence for ``graph_node_aliases`` (tenant- and snapshot-keyed node id aliases)."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Sequence

from agent_bom.graph.node_aliases import NODE_ALIAS_COLUMNS, resolve_with_server_children

NODE_ALIASES_DDL = """\
CREATE TABLE IF NOT EXISTS graph_node_aliases (
    tenant_id        TEXT NOT NULL DEFAULT 'default',
    alias_id         TEXT NOT NULL,
    canonical_id     TEXT NOT NULL,
    entity_type      TEXT NOT NULL DEFAULT '',
    identity_version TEXT NOT NULL DEFAULT '',
    scan_id          TEXT NOT NULL DEFAULT '',
    updated_at       TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, scan_id, alias_id)
);
CREATE INDEX IF NOT EXISTS idx_gna_canonical ON graph_node_aliases(tenant_id, canonical_id);
CREATE INDEX IF NOT EXISTS idx_gna_alias ON graph_node_aliases(tenant_id, alias_id, updated_at);
"""

_MAX_LOOKUP = 500
# An id that is a live node in the alias row's snapshot resolves to itself.
_LIVE_NODE = "SELECT 1 FROM graph_nodes n WHERE n.id = a.alias_id AND n.scan_id = a.scan_id AND n.tenant_id = a.tenant_id"


def upgrade_node_alias_key(conn: sqlite3.Connection) -> None:
    """Re-key a pre-snapshot alias table so each snapshot keeps its own binding."""
    pk = [row[1] for row in sorted(conn.execute("PRAGMA table_info(graph_node_aliases)").fetchall(), key=lambda row: row[5]) if row[5]]
    if pk == ["tenant_id", "scan_id", "alias_id"]:
        return
    columns = ", ".join(NODE_ALIAS_COLUMNS)
    conn.execute("ALTER TABLE graph_node_aliases RENAME TO graph_node_aliases_v9")
    conn.execute("DROP INDEX IF EXISTS idx_gna_canonical")
    conn.execute("DROP INDEX IF EXISTS idx_gna_alias")
    conn.executescript(NODE_ALIASES_DDL)
    conn.execute(f"INSERT INTO graph_node_aliases ({columns}) SELECT {columns} FROM graph_node_aliases_v9")  # nosec B608 - static columns
    conn.execute("DROP TABLE graph_node_aliases_v9")


def write_node_aliases(conn: sqlite3.Connection, rows: Sequence[tuple[str, ...]]) -> None:
    """Upsert one snapshot's alias rows; other snapshots' bindings are never touched.

    Rows are in :data:`NODE_ALIAS_COLUMNS` order (tenant, alias, ..., scan, ...).
    """
    if not rows:
        return
    placeholders = ", ".join("?" for _ in NODE_ALIAS_COLUMNS)
    updates = ", ".join(f"{column}=excluded.{column}" for column in NODE_ALIAS_COLUMNS[2:] if column != "scan_id")
    # Nodes are written first in the same transaction; an alias naming one of them is never recorded.
    conn.executemany(
        f"INSERT INTO graph_node_aliases ({', '.join(NODE_ALIAS_COLUMNS)}) SELECT {placeholders} "  # nosec B608 - static columns
        "WHERE NOT EXISTS (SELECT 1 FROM graph_nodes WHERE id = ? AND scan_id = ? AND tenant_id = ?) "
        f"ON CONFLICT(tenant_id, scan_id, alias_id) DO UPDATE SET {updates}",
        [(*row, row[1], row[5], row[0]) for row in rows],
    )


def resolve_node_aliases(conn: sqlite3.Connection, *, tenant_id: str, node_ids: Iterable[str], scan_id: str = "") -> dict[str, str]:
    """Map each requested id that is a recorded alias to its canonical id, within one tenant.

    A recorded alias equal to a node id that exists in the same snapshot is ignored.

    With ``scan_id`` the binding is the one that snapshot recorded; without it,
    the latest scan snapshot, matching the default graph read. Missing or
    ambiguous current bindings never fall back to an older snapshot.
    """
    ids = sorted({node_id for node_id in node_ids if node_id})[:_MAX_LOOKUP]
    if not ids:
        return {}
    return resolve_with_server_children(
        ids,
        lambda batch: _resolve_direct(conn, tenant_id, batch, scan_id),
        lambda batch: _live_ids(conn, tenant_id, batch, scan_id),
    )


def _snapshot_scope(alias: str, scan_id: str) -> tuple[str, list[str]]:
    if scan_id:
        return f"AND {alias}.scan_id = ?", [scan_id]
    return (
        f"AND {alias}.scan_id = (SELECT s.scan_id FROM graph_snapshots s WHERE s.tenant_id = {alias}.tenant_id "  # nosec B608 - alias is a fixed internal table alias
        "AND s.snapshot_kind = 'scan' ORDER BY s.created_at DESC, s.scan_id DESC LIMIT 1)",
        [],
    )


def _resolve_direct(conn: sqlite3.Connection, tenant_id: str, ids: list[str], scan_id: str) -> dict[str, str]:
    resolved: dict[str, str] = {}
    scope, params = _snapshot_scope("a", scan_id)
    for start in range(0, len(ids), _MAX_LOOKUP):
        batch = ids[start : start + _MAX_LOOKUP]
        placeholders = ",".join("?" for _ in batch)
        rows = conn.execute(
            f"SELECT alias_id, canonical_id FROM graph_node_aliases a WHERE tenant_id = ? AND alias_id IN ({placeholders}) {scope} "  # nosec B608
            f"AND NOT EXISTS ({_LIVE_NODE}) ORDER BY updated_at, scan_id",
            [tenant_id, *batch, *params],
        ).fetchall()
        resolved.update({str(row[0]): str(row[1]) for row in rows})
    return resolved


def _live_ids(conn: sqlite3.Connection, tenant_id: str, ids: list[str], scan_id: str) -> set[str]:
    """Ids that are nodes in the snapshot the alias reads are scoped to."""
    live: set[str] = set()
    scope, params = _snapshot_scope("n", scan_id)
    for start in range(0, len(ids), _MAX_LOOKUP):
        batch = ids[start : start + _MAX_LOOKUP]
        placeholders = ",".join("?" for _ in batch)
        rows = conn.execute(
            f"SELECT n.id FROM graph_nodes n WHERE n.tenant_id = ? AND n.id IN ({placeholders}) {scope}",  # nosec B608
            [tenant_id, *batch, *params],
        ).fetchall()
        live.update(str(row[0]) for row in rows)
    return live
