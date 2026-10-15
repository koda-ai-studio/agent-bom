"""SQLite persistence for ``graph_node_aliases`` (tenant- and snapshot-keyed node id aliases)."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Sequence

from agent_bom.graph.node_aliases import NODE_ALIAS_COLUMNS

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
    """Upsert one snapshot's alias rows; other snapshots' bindings are never touched."""
    if not rows:
        return
    placeholders = ", ".join("?" for _ in NODE_ALIAS_COLUMNS)
    updates = ", ".join(f"{column}=excluded.{column}" for column in NODE_ALIAS_COLUMNS[2:] if column != "scan_id")
    conn.executemany(
        f"INSERT INTO graph_node_aliases ({', '.join(NODE_ALIAS_COLUMNS)}) VALUES ({placeholders}) "  # nosec B608 - static columns
        f"ON CONFLICT(tenant_id, scan_id, alias_id) DO UPDATE SET {updates}",
        rows,
    )


def resolve_node_aliases(conn: sqlite3.Connection, *, tenant_id: str, node_ids: Iterable[str], scan_id: str = "") -> dict[str, str]:
    """Map each requested id that is a recorded alias to its canonical id, within one tenant.

    With ``scan_id`` the binding is the one that snapshot recorded; without it,
    the most recently written binding.
    """
    ids = sorted({node_id for node_id in node_ids if node_id})[:_MAX_LOOKUP]
    if not ids:
        return {}
    placeholders = ",".join("?" for _ in ids)
    scope, params = ("AND scan_id = ?", [scan_id]) if scan_id else ("", [])
    rows = conn.execute(
        f"SELECT alias_id, canonical_id FROM graph_node_aliases WHERE tenant_id = ? AND alias_id IN ({placeholders}) {scope} "  # nosec B608
        "ORDER BY updated_at, scan_id",
        [tenant_id, *ids, *params],
    ).fetchall()
    return {str(row[0]): str(row[1]) for row in rows}
