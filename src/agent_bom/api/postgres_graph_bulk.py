"""Bulk snapshot writes for the Postgres graph store: COPY into session staging, then one upsert per table.

The row-at-a-time path sent one ``INSERT ... ON CONFLICT`` per node, search
row and edge; at 5,000 agents that was about half of a push. Here each batch of
rows (``AGENT_BOM_GRAPH_WRITE_BATCH_SIZE``, default 1,000) is streamed with
``COPY`` into a transaction-scoped ``TEMP`` table with an ordinal, then written
by one ``INSERT ... SELECT DISTINCT ON (key) ... ORDER BY key, ordinal DESC ...
ON CONFLICT`` per table. One statement per batch, not per write, keeps each
statement well inside the session statement timeout (one statement for 229,000
edges exceeded the 15 s default). That keeps the row path's rules exactly:

* duplicates inside one write resolve last-wins: within a batch by the ordinal,
  across batches, applied in order, by the same ``ON CONFLICT DO UPDATE`` of
  every non-key column the row path uses;
* edges carry ``first_seen``/``valid_from`` forward from the superseded scan
  through the same join and scope predicate;
* the insert runs as the app role under row-level security, in the save's one
  transaction, so a failure part way rolls back the staging, the snapshot
  clearing and every row together;
* staging columns take the target tables' own types, so values convert exactly
  as an insert would (text, integer, double precision and jsonb).

``AGENT_BOM_PG_GRAPH_BULK_WRITE=0`` keeps the row path for one release. A
database that refuses ``TEMP`` tables falls back to it inside a savepoint.
"""

from __future__ import annotations

import logging
import weakref
from collections.abc import Iterable, Sequence
from typing import Any

from agent_bom.core.settings import SettingError, env_bool

logger = logging.getLogger(__name__)
# Connections whose current save staged; weak, so a closed connection drops out.
_staged: weakref.WeakSet[Any] = weakref.WeakSet()

BULK_SETTING = "AGENT_BOM_PG_GRAPH_BULK_WRITE"

NODE_COLUMNS = (
    "id", "entity_type", "label", "category_uid", "class_uid", "type_uid",
    "status", "risk_score", "severity", "severity_id",
    "first_seen", "last_seen", "attributes", "compliance_tags",
    "data_sources", "dimensions", "scan_id", "tenant_id",
)  # fmt: skip
NODE_KEY = ("id", "scan_id", "tenant_id")
SEARCH_COLUMNS = ("node_id", "tenant_id", "scan_id", "entity_type", "severity", "compliance_tags", "data_sources", "search_text")
SEARCH_KEY = ("node_id", "scan_id", "tenant_id")
EDGE_COLUMNS = (
    "source_id", "target_id", "relationship", "direction", "weight",
    "traversable", "first_seen", "last_seen", "valid_from", "valid_to",
    "confidence", "provenance", "source_scan_id", "source_run_id",
    "evidence", "activity_id", "scan_id", "tenant_id",
)  # fmt: skip
EDGE_KEY = ("source_id", "target_id", "relationship", "scan_id", "tenant_id")

STAGES = {
    "abom_stage_nodes": ("graph_nodes", NODE_COLUMNS),
    "abom_stage_node_search": ("graph_node_search", SEARCH_COLUMNS),
    "abom_stage_edges": ("graph_edges", EDGE_COLUMNS),
}


def bulk_enabled() -> bool:
    try:
        return env_bool(BULK_SETTING, True)
    except SettingError:
        return True


def begin(conn: Any) -> bool:
    """Decide this save's path: always clear the previous save's state, then stage when the bulk path is on."""
    _staged.discard(conn)
    return bulk_enabled() and open_stages(conn)


def open_stages(conn: Any) -> bool:
    """Create this transaction's staging tables; False (nothing changed) when the role may not create TEMP tables."""
    _staged.discard(conn)
    if not (hasattr(conn, "transaction") and hasattr(conn, "cursor")):
        return False  # light test doubles expose execute/executemany only, as _execute_many_batched allows
    try:
        import psycopg
    except ImportError:
        return False  # without the driver there is no PostgreSQL connection to stage on
    try:
        with conn.transaction():  # a savepoint: a refusal leaves the save's transaction usable
            for stage, (table, columns) in STAGES.items():
                conn.execute(
                    f"CREATE TEMP TABLE IF NOT EXISTS {stage} ON COMMIT DROP AS "  # nosec B608 - fixed internal names
                    f"SELECT {', '.join(columns)}, 0::bigint AS ord FROM {table} WITH NO DATA"
                )
                conn.execute(f"TRUNCATE {stage}")  # nosec B608 - fixed internal name
    except psycopg.errors.InsufficientPrivilege:
        logger.warning("Graph bulk write unavailable (TEMP tables not permitted); writing rows one at a time")
        return False
    _staged.add(conn)
    return True


def staged(conn: Any) -> bool:
    """Whether this connection's current save opened the staging tables (set afresh by every save's node write)."""
    return conn in _staged


def copy_stage(conn: Any, stage: str, rows: Iterable[Sequence[Any]], *, start: int) -> int:
    """Stream ``rows`` into ``stage`` with their ordinals from ``start``; return the next ordinal."""
    columns = STAGES[stage][1]
    ordinal = start
    with conn.cursor() as cursor:
        with cursor.copy(f"COPY {stage} ({', '.join(columns)}, ord) FROM STDIN") as copy:  # nosec B608 - fixed internal names
            for row in rows:
                copy.write_row((*row[: len(columns)], ordinal))
                ordinal += 1
    return ordinal


def _latest(stage: str, columns: Sequence[str], key: Sequence[str]) -> str:
    return (
        f"SELECT DISTINCT ON ({', '.join(key)}) {', '.join(columns)} FROM {stage} "  # nosec B608 - fixed internal names
        f"ORDER BY {', '.join(key)}, ord DESC"
    )


def _updates(columns: Sequence[str], key: Sequence[str]) -> str:
    return ", ".join(f"{column} = EXCLUDED.{column}" for column in columns if column not in key)


def flush_nodes(conn: Any) -> None:
    for stage, table, key in (("abom_stage_nodes", "graph_nodes", NODE_KEY), ("abom_stage_node_search", "graph_node_search", SEARCH_KEY)):
        columns = STAGES[stage][1]
        conn.execute(
            f"INSERT INTO {table} ({', '.join(columns)}) {_latest(stage, columns, key)} "  # nosec B608 - fixed internal names
            f"ON CONFLICT ({', '.join(key)}) DO UPDATE SET {_updates(columns, key)}"
        )
        conn.execute(f"TRUNCATE {stage}")  # nosec B608 - fixed internal name


def flush_edges(conn: Any, *, select_sql: str, previous_scan: str | None) -> None:
    """Upsert the staged edges with the row path's own projection and previous-scan join (``select_sql``)."""
    conn.execute(select_sql, (previous_scan,))
    conn.execute("TRUNCATE abom_stage_edges")


def latest_edges_sql() -> str:
    return _latest("abom_stage_edges", EDGE_COLUMNS, EDGE_KEY)


__all__ = [
    "BULK_SETTING",
    "EDGE_COLUMNS",
    "NODE_COLUMNS",
    "SEARCH_COLUMNS",
    "begin",
    "bulk_enabled",
    "copy_stage",
    "flush_edges",
    "flush_nodes",
    "latest_edges_sql",
    "open_stages",
    "staged",
]
