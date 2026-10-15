"""Postgres persistence for ``graph_node_aliases`` (tenant-keyed node id aliases, FORCE RLS)."""

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
                    PRIMARY KEY (tenant_id, alias_id)
                )
                """,
    "CREATE INDEX IF NOT EXISTS idx_pg_graph_node_aliases_canonical ON graph_node_aliases(tenant_id, canonical_id)",
)
_MAX_LOOKUP = 500
_UPSERT_SQL = (
    f"INSERT INTO graph_node_aliases ({', '.join(NODE_ALIAS_COLUMNS)}) VALUES ({', '.join('%s' for _ in NODE_ALIAS_COLUMNS)}) "  # nosec B608
    f"ON CONFLICT (tenant_id, alias_id) DO UPDATE SET {', '.join(f'{c} = EXCLUDED.{c}' for c in NODE_ALIAS_COLUMNS[2:])}"
)


def write_node_aliases(conn: Any, rows: Sequence[tuple[str, ...]]) -> None:
    """Upsert alias rows inside the caller's tenant-bound transaction."""
    if rows:
        with conn.cursor() as cursor:
            cursor.executemany(_UPSERT_SQL, rows)


def resolve_node_aliases(conn: Any, *, tenant_id: str, node_ids: Iterable[str]) -> dict[str, str]:
    """Map recorded alias ids to canonical ids; RLS and the predicate both bind the tenant."""
    ids = sorted({node_id for node_id in node_ids if node_id})[:_MAX_LOOKUP]
    if not ids:
        return {}
    rows = conn.execute(
        "SELECT alias_id, canonical_id FROM graph_node_aliases WHERE tenant_id = %s AND alias_id = ANY(%s)",
        (tenant_id, ids),
    ).fetchall()
    return {str(row[0]): str(row[1]) for row in rows}


class PostgresGraphAliasMixin:
    """Resolve node ids that canonicalization replaced, within one tenant."""

    _pool: Any

    def resolve_node_aliases(self, *, tenant_id: str = "", node_ids: Iterable[str]) -> dict[str, str]:
        with _tenant_connection(self._pool) as conn:
            return resolve_node_aliases(conn, tenant_id=normalize_graph_tenant_id(tenant_id), node_ids=node_ids)
