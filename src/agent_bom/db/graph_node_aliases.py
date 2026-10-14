"""SQLite persistence for ``graph_node_aliases`` (tenant-keyed node id aliases)."""

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
    PRIMARY KEY (tenant_id, alias_id)
);
CREATE INDEX IF NOT EXISTS idx_gna_canonical ON graph_node_aliases(tenant_id, canonical_id);
"""

_MAX_LOOKUP = 500


def write_node_aliases(conn: sqlite3.Connection, rows: Sequence[tuple[str, ...]]) -> None:
    """Upsert alias rows; a later snapshot re-points an alias to its newest canonical id."""
    if not rows:
        return
    placeholders = ", ".join("?" for _ in NODE_ALIAS_COLUMNS)
    updates = ", ".join(f"{column}=excluded.{column}" for column in NODE_ALIAS_COLUMNS[2:])
    conn.executemany(
        f"INSERT INTO graph_node_aliases ({', '.join(NODE_ALIAS_COLUMNS)}) VALUES ({placeholders}) "  # nosec B608 - static columns
        f"ON CONFLICT(tenant_id, alias_id) DO UPDATE SET {updates}",
        rows,
    )


def resolve_node_aliases(conn: sqlite3.Connection, *, tenant_id: str, node_ids: Iterable[str]) -> dict[str, str]:
    """Map each requested id that is a recorded alias to its canonical id, within one tenant."""
    ids = sorted({node_id for node_id in node_ids if node_id})[:_MAX_LOOKUP]
    if not ids:
        return {}
    placeholders = ",".join("?" for _ in ids)
    rows = conn.execute(
        f"SELECT alias_id, canonical_id FROM graph_node_aliases WHERE tenant_id = ? AND alias_id IN ({placeholders})",  # nosec B608
        [tenant_id, *ids],
    ).fetchall()
    return {str(row[0]): str(row[1]) for row in rows}
