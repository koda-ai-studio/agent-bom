"""Copy a one-source current-estate projection from PostgreSQL as rows.

Loading a PostgreSQL snapshot into graph objects and writing it back held the
API's interpreter lock for the whole first build after a large push, and graph
reads in that window waited on it. When the current view has exactly one source
snapshot, the projection is that snapshot under the projection's identity, so
its rows are streamed from server-side cursors, one consistent snapshot, into
the projection file in batches.

The copy runs only when it provably equals the load-and-rewrite result, with
the same conditions as the SQLite copy:

* the source's committed revision is the one the build resolved;
* every agent node already carries this runtime's agent context, stamped with
  its snapshot wherever an edge had no source scan;
* the source's stored path index is this runtime's derivation.

Text columns are copied as stored: both backends serialize them with the same
calls. JSONB columns are copied as PostgreSQL's text for them; JSONB keeps no
key order, so they equal the rewrite's values, not its key order. Anything else
returns False with nothing written, and the caller takes the load-and-rewrite
path.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path
from typing import Any

from agent_bom.api import current_graph_pg_copy_child
from agent_bom.api.graph_store_support import _CREATE_PRESET_TABLE_SQLITE
from agent_bom.db import graph_store as sqlite_graph_store
from agent_bom.db.graph_node_search import ensure_search_index
from agent_bom.db.graph_revision import revision_tokens
from agent_bom.db.graph_store_write import _check_snapshot_writable, _clear_snapshot_rows, checkpoint_wal
from agent_bom.db.sqlite_bulk_cache import snapshot_bulk_cache
from agent_bom.graph.agent_context import AGENT_CONTEXT_SCHEMA_VERSION
from agent_bom.graph.snapshot_paths import stored_paths_current

logger = logging.getLogger(__name__)

BATCH_ROWS = 2000
# Copied as they are apart from the projection's scan id.
_VERBATIM_TABLES = ("graph_nodes", "graph_edges", "graph_node_aliases", "graph_node_search", "interaction_risks")
_COPIED_TABLES = frozenset((*_VERBATIM_TABLES, "attack_paths", "graph_attack_paths"))

# A node stored without its generated identity gets a legacy one a rewrite would derive.
_UNRECORDED_IDENTITY = (
    "SELECT 1 FROM graph_nodes WHERE tenant_id = %s AND scan_id = %s "
    "AND COALESCE(attributes::jsonb ->> '_agent_bom_canonical_id', '') = '' LIMIT 1"
)
_UNCONTEXTED_AGENT = (
    "SELECT 1 FROM graph_nodes WHERE tenant_id = %s AND scan_id = %s AND entity_type = 'agent' "
    "AND COALESCE(attributes::jsonb #>> '{agent_context,schema_version}', '') <> %s LIMIT 1"
)
# Snapshots written before agent context stamped its own snapshot on edges with
# no source scan record "", which a rewrite would replace.
_UNSTAMPED_AGENT = (
    "SELECT 1 FROM graph_nodes WHERE tenant_id = %s AND scan_id = %s AND entity_type = 'agent' "
    "AND jsonb_path_exists(attributes::jsonb -> 'agent_context', 'lax $.**.source_scan_id ? (@ == \"\")') LIMIT 1"
)


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    decoded = json.loads(value or "{}")
    return decoded if isinstance(decoded, dict) else {}


def _json_text(value: Any) -> Any:
    return value if value is None or isinstance(value, str) else json.dumps(value)


def _source_snapshot(pg: Any, *, tenant: str, source_scan: str, expected_revision: str) -> dict[str, Any] | None:
    """The source snapshot row when the copy would equal a rewrite, else None."""
    row = pg.execute(
        "SELECT read_revision, analysis_status, node_type_counts, risk_summary, node_count, edge_count "
        "FROM graph_snapshots WHERE tenant_id = %s AND scan_id = %s",
        (tenant, source_scan),
    ).fetchone()
    if row is None or str(row[0]) != expected_revision or row[2] is None:
        return None
    raw_status = _json_object(row[1])
    if not stored_paths_current(raw_status):
        return None
    if pg.execute(_UNRECORDED_IDENTITY, (tenant, source_scan)).fetchone():
        return None
    if pg.execute(_UNCONTEXTED_AGENT, (tenant, source_scan, AGENT_CONTEXT_SCHEMA_VERSION)).fetchone():
        return None
    if pg.execute(_UNSTAMPED_AGENT, (tenant, source_scan)).fetchone():
        return None
    return {
        "analysis_status": raw_status,
        "node_type_counts": _json_text(row[2]),
        "risk_summary": _json_text(row[3]),
        "node_count": row[4],
        "edge_count": row[5],
    }


def _column_types(pg: Any, table: str) -> dict[str, str]:
    rows = pg.execute(
        "SELECT column_name, data_type FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = %s",
        (table,),
    ).fetchall()
    return {str(name): str(kind) for name, kind in rows}


def _projection_columns(conn: sqlite3.Connection, table: str) -> list[str]:
    return [str(row[1]) for row in conn.execute(f"PRAGMA main.table_info({table})")]  # nosec B608 - fixed internal table names


def _copy_table(pg: Any, conn: sqlite3.Connection, table: str, *, overrides: dict[str, Any], tenant: str, source_scan: str) -> None:
    if table not in _COPIED_TABLES:
        raise ValueError(f"Unsupported projection table: {table}")
    types = _column_types(pg, table)
    columns = [column for column in _projection_columns(conn, table) if column in types]
    # Rows arrive in projection column order, overrides bound as values and JSONB as its text,
    # so each batch goes to SQLite as fetched, without per-row Python work.
    expressions = ["%s::text" if column in overrides else f"{column}::text" if types[column] == "jsonb" else column for column in columns]
    params = [*(overrides[column] for column in columns if column in overrides), tenant, source_scan]
    insert = f"INSERT INTO main.{table} ({', '.join(columns)}) VALUES ({', '.join('?' * len(columns))})"  # nosec B608 - columns come from PRAGMA table_info of a fixed table
    select = f"SELECT {', '.join(expressions)} FROM {table} WHERE tenant_id = %s AND scan_id = %s"  # nosec B608 - columns come from information_schema of a fixed table
    with pg.cursor(name=f"current_projection_{table}") as cursor:
        cursor.itersize = BATCH_ROWS
        cursor.execute(select, params)
        while rows := cursor.fetchmany(BATCH_ROWS):
            conn.executemany(insert, rows)


def _copy(
    pg: Any,
    conn: sqlite3.Connection,
    *,
    tenant: str,
    source_scan: str,
    expected_revision: str,
    identity: str,
    created_at: str,
    write_generation: str,
    evidence_manifest_sha256: str,
) -> bool:
    from agent_bom.api.current_graph_copy import projection_status

    source = _source_snapshot(pg, tenant=tenant, source_scan=source_scan, expected_revision=expected_revision)
    if source is None:
        return False
    _check_snapshot_writable(conn, tenant=tenant, scan=identity, snapshot_kind="correlation", correlation_id=identity)
    _clear_snapshot_rows(conn, tenant=tenant, scan=identity)
    conn.execute("DELETE FROM main.graph_node_search WHERE tenant_id = ? AND scan_id = ?", (tenant, identity))
    for table in _VERBATIM_TABLES:
        _copy_table(pg, conn, table, overrides={"scan_id": identity}, tenant=tenant, source_scan=source_scan)
    _copy_table(
        pg, conn, "attack_paths", overrides={"scan_id": identity, "computed_at": created_at}, tenant=tenant, source_scan=source_scan
    )
    generation, read_revision = revision_tokens(write_generation)
    conn.execute(
        """
        INSERT INTO main.graph_snapshots
            (scan_id, tenant_id, created_at, node_count, edge_count, risk_summary,
             node_type_counts, analysis_status, snapshot_kind, correlation_id,
             evidence_manifest_sha256, snapshot_generation, read_revision)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'correlation', ?, ?, ?, ?)
        """,
        (
            identity,
            tenant,
            created_at,
            source["node_count"],
            source["edge_count"],
            source["risk_summary"],
            source["node_type_counts"],
            projection_status(source["analysis_status"]),
            identity,
            evidence_manifest_sha256,
            generation,
            read_revision,
        ),
    )
    path_overrides = {"scan_id": identity, "snapshot_generation": generation, "computed_at": created_at}
    _copy_table(pg, conn, "graph_attack_paths", overrides=path_overrides, tenant=tenant, source_scan=source_scan)
    return True


def copy_postgres_source(
    store: Any,
    *,
    tenant: str,
    source_scan: str,
    expected_revision: str,
    identity: str,
    created_at: str,
    write_generation: str,
    evidence_manifest_sha256: str,
) -> bool:
    """Copy one PostgreSQL source snapshot into the projection in a child process; False when it did not apply.

    The child holds none of the API's interpreter lock while it streams rows.
    A decline, a failure, a timeout or a crash all leave nothing promoted, and
    the caller rebuilds in process.
    """
    return current_graph_pg_copy_child.copy_in_child(
        str(store._cache_path),
        tenant=tenant,
        source_scan=source_scan,
        expected_revision=expected_revision,
        identity=identity,
        created_at=created_at,
        write_generation=write_generation,
        evidence_manifest_sha256=evidence_manifest_sha256,
    )


def copy_postgres_rows(
    pool: Any,
    cache_path: str,
    *,
    tenant: str,
    source_scan: str,
    expected_revision: str,
    identity: str,
    created_at: str,
    write_generation: str,
    evidence_manifest_sha256: str,
) -> bool:
    """Copy one PostgreSQL source snapshot into the projection file; False (nothing written) when it would not equal a rewrite."""
    import psycopg

    from agent_bom.api.postgres_common import _tenant_connection

    try:
        # One repeatable-read snapshot: every table is read at the revision checked first.
        with _tenant_connection(pool, repeatable_read=True) as pg:
            with sqlite_graph_store.open_graph_db(Path(cache_path)) as conn:
                with snapshot_bulk_cache(conn):
                    conn.execute("BEGIN IMMEDIATE")
                    copied = False
                    try:
                        conn.execute(_CREATE_PRESET_TABLE_SQLITE)
                        ensure_search_index(conn)
                        copied = _copy(
                            pg,
                            conn,
                            tenant=tenant,
                            source_scan=source_scan,
                            expected_revision=expected_revision,
                            identity=identity,
                            created_at=created_at,
                            write_generation=write_generation,
                            evidence_manifest_sha256=evidence_manifest_sha256,
                        )
                    finally:
                        # Nothing is written unless the whole copy succeeded and applied.
                        if copied:
                            conn.commit()
                        else:
                            conn.rollback()
                if copied:
                    checkpoint_wal(conn)
    except psycopg.Error as exc:
        # A source the copy cannot read as rows (for example attributes that are not JSON) still rebuilds.
        logger.warning("Current graph row copy from PostgreSQL declined (%s); rebuilding instead", type(exc).__name__)
        return False
    return copied


__all__ = ["BATCH_ROWS", "copy_postgres_rows", "copy_postgres_source"]
