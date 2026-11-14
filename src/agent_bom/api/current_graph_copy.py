"""Copy a one-source current-estate projection in SQL instead of through Python.

When the current view has exactly one source snapshot, the projection is that
snapshot under the projection's identity. Loading it into a ``UnifiedGraph``
and writing it back was about 90% of a cold build at 5,000 agents, so on a
SQLite source the rows are copied with ``INSERT ... SELECT`` in one
transaction on the projection file, with the source attached read-only.

The copy runs only when it provably equals the load-and-rewrite result:

* the source's committed revision is the one the build resolved;
* every agent node already carries this runtime's agent context, which the
  rewrite would otherwise compute;
* the source's stored path index is this runtime's derivation, which the
  rewrite would otherwise rebuild.

Anything else returns False and the caller takes the load-and-rewrite path.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.graph_store_support import _CREATE_PRESET_TABLE_SQLITE
from agent_bom.db import graph_store as sqlite_graph_store
from agent_bom.db.graph_node_search import ensure_search_index
from agent_bom.db.graph_revision import revision_tokens
from agent_bom.db.graph_store_write import _check_snapshot_writable, _clear_snapshot_rows, checkpoint_wal
from agent_bom.db.sqlite_bulk_cache import snapshot_bulk_cache
from agent_bom.graph.adjacency_page import CURRENT_ESTATE_SCAN_PREFIX
from agent_bom.graph.agent_context import AGENT_CONTEXT_SCHEMA_VERSION
from agent_bom.graph.analysis import analysis_status_map_from_dict, analysis_status_map_to_dict, merge_analysis_statuses
from agent_bom.graph.snapshot_paths import PATHS_ANALYSIS_KEY, stored_paths_current

# Copied as they are apart from the projection's scan id.
_VERBATIM_TABLES = ("graph_nodes", "graph_edges", "graph_node_aliases", "graph_node_search", "interaction_risks")


def _columns(conn: sqlite3.Connection, schema: str, table: str) -> list[str]:
    return [str(row[1]) for row in conn.execute(f"PRAGMA {schema}.table_info({table})")]  # nosec B608 - fixed schema and table names


def _copy_rows(conn: sqlite3.Connection, table: str, *, overrides: dict[str, Any], tenant: str, source_scan: str) -> None:
    source_columns = set(_columns(conn, "src", table))
    columns = [column for column in _columns(conn, "main", table) if column in source_columns]
    select = ", ".join("?" if column in overrides else column for column in columns)
    params = [overrides[column] for column in columns if column in overrides]
    conn.execute(
        f"INSERT INTO main.{table} ({', '.join(columns)}) SELECT {select} FROM src.{table} WHERE tenant_id = ? AND scan_id = ?",  # nosec B608 - columns come from PRAGMA table_info of fixed tables
        (*params, tenant, source_scan),
    )


def _source_snapshot(conn: sqlite3.Connection, *, tenant: str, source_scan: str, expected_revision: str) -> dict[str, Any] | None:
    """The source snapshot row when the copy would equal a rewrite, else None."""
    if not conn.execute("SELECT 1 FROM src.sqlite_master WHERE name = 'graph_node_search'").fetchone():
        return None
    row = conn.execute(
        "SELECT read_revision, analysis_status, node_type_counts FROM src.graph_snapshots WHERE tenant_id = ? AND scan_id = ?",
        (tenant, source_scan),
    ).fetchone()
    if row is None or str(row[0]) != expected_revision or row[2] is None:
        return None
    raw_status = json.loads(row[1] or "{}")
    if not stored_paths_current(raw_status):
        return None
    uncontexted = conn.execute(
        "SELECT 1 FROM src.graph_nodes WHERE tenant_id = ? AND scan_id = ? AND entity_type = 'agent' "
        "AND COALESCE(json_extract(attributes, '$.agent_context.schema_version'), '') != ? LIMIT 1",
        (tenant, source_scan, AGENT_CONTEXT_SCHEMA_VERSION),
    ).fetchone()
    if uncontexted:
        return None
    # Snapshots written before agent context stamped its own snapshot on edges
    # with no source scan record "", which a rewrite would replace.
    unstamped = conn.execute(
        "SELECT 1 FROM src.graph_nodes AS node, json_tree(node.attributes, '$.agent_context') AS item "
        "WHERE node.tenant_id = ? AND node.scan_id = ? AND node.entity_type = 'agent' "
        "AND item.key = 'source_scan_id' AND item.atom = '' LIMIT 1",
        (tenant, source_scan),
    ).fetchone()
    if unstamped:
        return None
    return {"analysis_status": raw_status}


def projection_status(raw_status: dict[str, Any]) -> str:
    """The same status the rewrite stamps: merged source statuses, then the path index's own."""
    statuses = analysis_status_map_from_dict(raw_status)
    paths = statuses.pop(PATHS_ANALYSIS_KEY)
    merged = merge_analysis_statuses([statuses])
    merged[PATHS_ANALYSIS_KEY] = paths
    return json.dumps(analysis_status_map_to_dict(merged))


def _copy(
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
    source = _source_snapshot(conn, tenant=tenant, source_scan=source_scan, expected_revision=expected_revision)
    if source is None:
        return False
    _check_snapshot_writable(conn, tenant=tenant, scan=identity, snapshot_kind="correlation", correlation_id=identity)
    _clear_snapshot_rows(conn, tenant=tenant, scan=identity)
    conn.execute("DELETE FROM main.graph_node_search WHERE tenant_id = ? AND scan_id = ?", (tenant, identity))
    for table in _VERBATIM_TABLES:
        _copy_rows(conn, table, overrides={"scan_id": identity}, tenant=tenant, source_scan=source_scan)
    _copy_rows(conn, "attack_paths", overrides={"scan_id": identity, "computed_at": created_at}, tenant=tenant, source_scan=source_scan)
    generation, read_revision = revision_tokens(write_generation)
    conn.execute(
        """
        INSERT INTO main.graph_snapshots
            (scan_id, tenant_id, created_at, node_count, edge_count, risk_summary,
             node_type_counts, analysis_status, snapshot_kind, correlation_id,
             evidence_manifest_sha256, snapshot_generation, read_revision)
        SELECT ?, tenant_id, ?, node_count, edge_count, risk_summary, node_type_counts, ?, 'correlation', ?, ?, ?, ?
        FROM src.graph_snapshots WHERE tenant_id = ? AND scan_id = ?
        """,
        (
            identity,
            created_at,
            projection_status(source["analysis_status"]),
            identity,
            evidence_manifest_sha256,
            generation,
            read_revision,
            tenant,
            source_scan,
        ),
    )
    path_overrides = {"scan_id": identity, "snapshot_generation": generation, "computed_at": created_at}
    _copy_rows(conn, "graph_attack_paths", overrides=path_overrides, tenant=tenant, source_scan=source_scan)
    return True


def copy_single_source(
    projection_path: str | Path,
    source_path: str | Path,
    *,
    tenant: str,
    source_scan: str,
    expected_revision: str,
    identity: str,
    created_at: str,
    write_generation: str,
    evidence_manifest_sha256: str,
) -> bool:
    """Copy one source snapshot into the projection; False (nothing written) when the copy would not equal a rewrite."""
    with sqlite_graph_store.open_graph_db(Path(projection_path)) as conn:
        conn.execute("ATTACH DATABASE ? AS src", (str(source_path),))
        try:
            with snapshot_bulk_cache(conn):
                conn.execute("BEGIN IMMEDIATE")
                copied = False
                try:
                    conn.execute(_CREATE_PRESET_TABLE_SQLITE)
                    ensure_search_index(conn)
                    copied = _copy(
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
                if not copied:
                    return False
        finally:
            conn.execute("DETACH DATABASE src")
        checkpoint_wal(conn)
    return True


def copy_current_projection(
    store: Any, tenant: str, identity: str, created_at: str, revisions: tuple[tuple[str, str], ...], digest: str
) -> bool:
    """Copy the current view's only source snapshot from a SQLite or PostgreSQL store; False otherwise."""
    present = [(scan, generation) for scan, generation in revisions if generation]
    if len(present) != 1:
        return False
    scan, generation = present[0]
    copy = {
        "tenant": tenant,
        "source_scan": scan,
        "expected_revision": generation,
        "identity": identity,
        "created_at": created_at,
        "write_generation": identity.removeprefix(CURRENT_ESTATE_SCAN_PREFIX),
        "evidence_manifest_sha256": "sha256:" + digest,
    }
    backend = store._graph_store
    if isinstance(backend, SQLiteGraphStore):
        source_path = getattr(backend, "_db_path", None)
        return bool(source_path) and copy_single_source(store._cache_path, str(source_path), **copy)
    if _is_postgres(backend):
        from agent_bom.api import current_graph_pg_copy

        return current_graph_pg_copy.copy_postgres_source(store, **copy)
    return False


def _is_postgres(backend: Any) -> bool:
    try:
        from agent_bom.api.postgres_graph import PostgresGraphStore
    except ImportError:  # the postgres extra is not installed
        return False
    return isinstance(backend, PostgresGraphStore)


def stamp_read_revision(cache_path: str, tenant: str, identity: str) -> None:
    """Give a projection the paging revision its identity names.

    Identical source generations resolve to the same paging revision across
    workers and restarts, even though each owns its own cache.
    """
    with sqlite3.connect(cache_path) as conn:
        conn.execute(
            "UPDATE graph_snapshots SET read_revision = ? WHERE tenant_id = ? AND scan_id = ?",
            (identity.removeprefix(CURRENT_ESTATE_SCAN_PREFIX), tenant, identity),
        )


def materialized_by_copy(
    store: Any, tenant: str, identity: str, created_at: str, revisions: tuple[tuple[str, str], ...], digest: str
) -> bool:
    """Materialize the projection by copy when that applies; True once the projection exists."""
    try:
        if not copy_current_projection(store, tenant, identity, created_at, revisions, digest):
            return False
    except ValueError:
        # Concurrent workers may commit this identical immutable projection.
        if not store._projection_store.snapshot_identity(tenant_id=tenant, scan_id=identity)[1]:
            raise
        return True
    stamp_read_revision(store._cache_path, tenant, identity)
    return True


__all__ = ["copy_current_projection", "copy_single_source", "materialized_by_copy", "projection_status", "stamp_read_revision"]
