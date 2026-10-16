"""Postgres persistence for ``graph_node_aliases`` (tenant- and snapshot-keyed node id aliases, FORCE RLS)."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from agent_bom.api.postgres_common import _tenant_connection
from agent_bom.db.graph_store_schema import normalize_graph_tenant_id
from agent_bom.graph.node_aliases import NODE_ALIAS_COLUMNS

NODE_ALIASES_DDL: tuple[str, ...] = (
    """
                CREATE TABLE IF NOT EXISTS graph_node_aliases (
                    tenant_id TEXT NOT NULL DEFAULT 'default',
                    alias_id TEXT NOT NULL,
                    canonical_id TEXT NOT NULL,
                    entity_type TEXT NOT NULL DEFAULT '',
                    identity_version TEXT NOT NULL DEFAULT '',
                    scan_id TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY (tenant_id, scan_id, alias_id)
                )
                """,
    "CREATE INDEX IF NOT EXISTS idx_pg_graph_node_aliases_canonical ON graph_node_aliases(tenant_id, canonical_id)",
    # Tables created before aliases were snapshot-scoped are keyed (tenant_id, alias_id).
    """
                DO $$
                DECLARE pk_name TEXT;
                BEGIN
                    SELECT c.conname INTO pk_name FROM pg_constraint c
                    WHERE c.conrelid = to_regclass('graph_node_aliases') AND c.contype = 'p';
                    IF pk_name IS NOT NULL AND NOT EXISTS (
                        SELECT 1 FROM pg_constraint c
                        JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY(c.conkey)
                        WHERE c.conrelid = to_regclass('graph_node_aliases') AND c.contype = 'p' AND a.attname = 'scan_id'
                    ) THEN
                        EXECUTE format('ALTER TABLE graph_node_aliases DROP CONSTRAINT %I', pk_name);
                        ALTER TABLE graph_node_aliases ADD CONSTRAINT graph_node_aliases_pkey PRIMARY KEY (tenant_id, scan_id, alias_id);
                    END IF;
                END
                $$
                """,
    "CREATE INDEX IF NOT EXISTS idx_pg_graph_node_aliases_alias ON graph_node_aliases(tenant_id, alias_id, updated_at)",
)
_MAX_LOOKUP = 500
# An id that is a live node in the alias row's snapshot resolves to itself.
# An alias never shadows a node that exists in the same snapshot.
_RESOLVE_IN_SNAPSHOT_SQL = (
    "SELECT alias_id, canonical_id FROM graph_node_aliases a WHERE tenant_id = %s AND alias_id = ANY(%s) AND scan_id = %s"
    " AND NOT EXISTS (SELECT 1 FROM graph_nodes n WHERE n.id = a.alias_id AND n.scan_id = a.scan_id AND n.tenant_id = a.tenant_id)"
)
_RESOLVE_LATEST_SQL = (
    "SELECT alias_id, canonical_id FROM graph_node_aliases a WHERE tenant_id = %s AND alias_id = ANY(%s)"
    " AND NOT EXISTS (SELECT 1 FROM graph_nodes n WHERE n.id = a.alias_id AND n.scan_id = a.scan_id AND n.tenant_id = a.tenant_id)"
    " AND a.scan_id = (SELECT s.scan_id FROM graph_snapshots s WHERE s.tenant_id = a.tenant_id"
    " AND s.snapshot_kind = 'scan' ORDER BY s.created_at DESC, s.scan_id DESC LIMIT 1)"
)
# Nodes are written first in the same transaction; an alias naming one of them is never recorded.
_UPSERT_SQL = (
    f"INSERT INTO graph_node_aliases ({', '.join(NODE_ALIAS_COLUMNS)}) SELECT {', '.join('%s' for _ in NODE_ALIAS_COLUMNS)} "  # nosec B608
    "WHERE NOT EXISTS (SELECT 1 FROM graph_nodes WHERE id = %s AND scan_id = %s AND tenant_id = %s) "
    "ON CONFLICT (tenant_id, scan_id, alias_id) DO UPDATE SET "
    + ", ".join(f"{column} = EXCLUDED.{column}" for column in NODE_ALIAS_COLUMNS[2:] if column != "scan_id")
)


def write_node_aliases(conn: Any, rows: Sequence[tuple[str, ...]]) -> None:
    """Upsert alias rows inside the caller's tenant-bound transaction."""
    if rows:
        with conn.cursor() as cursor:
            cursor.executemany(_UPSERT_SQL, [(*row, row[1], row[5], row[0]) for row in rows])


def resolve_node_aliases(conn: Any, *, tenant_id: str, node_ids: Iterable[str], scan_id: str = "") -> dict[str, str]:
    """Map recorded alias ids to canonical ids; RLS and the predicate both bind the tenant.

    A recorded alias equal to a node id that exists in the same snapshot is ignored.

    With ``scan_id`` the binding is the one that snapshot recorded; without it,
    the latest scan snapshot, matching the default graph read. Missing or
    ambiguous current bindings never fall back to an older snapshot.
    """
    ids = sorted({node_id for node_id in node_ids if node_id})[:_MAX_LOOKUP]
    if not ids:
        return {}
    if scan_id:
        sql = _RESOLVE_IN_SNAPSHOT_SQL
        params: tuple[Any, ...] = (tenant_id, ids, scan_id)
    else:
        sql = _RESOLVE_LATEST_SQL
        params = (tenant_id, ids)
    rows = conn.execute(sql, params).fetchall()
    return {str(row[0]): str(row[1]) for row in rows}


class PostgresGraphAliasMixin:
    """Resolve node ids that canonicalization replaced, within one tenant."""

    _pool: Any

    def resolve_node_aliases(self, *, tenant_id: str = "", node_ids: Iterable[str], scan_id: str = "") -> dict[str, str]:
        with _tenant_connection(self._pool) as conn:
            return resolve_node_aliases(conn, tenant_id=normalize_graph_tenant_id(tenant_id), node_ids=node_ids, scan_id=scan_id)
