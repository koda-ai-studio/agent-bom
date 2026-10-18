"""Connection, search-index and row-mapping primitives for the SQLite graph store."""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import ExitStack, closing, contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass

from agent_bom.api.graph_edge_query import _edge_from_row as sqlite_edge_from_row
from agent_bom.api.graph_store_support import (
    _API_GRAPH_TENANT_TABLE_KEYS,
    _CREATE_PRESET_TABLE_SQLITE,
    _escape_like_query,
)
from agent_bom.api.storage.sqlite_graph_search import ensure_search_index
from agent_bom.db import graph_store as sqlite_graph_store
from agent_bom.db.graph_bootstrap import ensure_read_schema, invalidate_read_schema
from agent_bom.db.graph_node_aliases import resolve_node_aliases
from agent_bom.db.graph_node_search import sqlite_node_from_row
from agent_bom.db.graph_write_admission import graph_writer_admission
from agent_bom.graph import (
    UnifiedEdge,
    UnifiedNode,
)
from agent_bom.graph.ports import GraphStoreProtocol as GraphStoreProtocol


class SQLiteGraphStoreBase:
    def __init__(self, db_path: str | Path | None = None) -> None:
        self._db_path = Path(db_path or sqlite_graph_store.default_graph_db_path()).expanduser()

    def _open_rw_conn(self) -> sqlite3.Connection:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with graph_writer_admission(self._db_path), ExitStack() as cleanup:
            conn = sqlite3.connect(str(self._db_path), timeout=10)
            cleanup.callback(conn.close)
            conn.row_factory = sqlite3.Row
            sqlite_graph_store._init_db(conn)
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(_CREATE_PRESET_TABLE_SQLITE)
            ensure_search_index(conn)
            sqlite_graph_store._backfill_empty_tenant_ids(conn, _API_GRAPH_TENANT_TABLE_KEYS)
            conn.commit()
            cleanup.pop_all()
            return conn

    @contextmanager
    def _write_conn(self) -> Iterator[sqlite3.Connection]:
        with graph_writer_admission(self._db_path):
            conn = self._open_rw_conn()
            try:
                yield conn
            finally:
                conn.close()

    def check_readiness(self) -> None:
        """Initialize empty storage once, then validate schema without graph scans."""
        try:
            conn = self._open_ro_conn(initialize_missing=True)
            assert conn is not None
            with closing(conn):
                conn.execute("PRAGMA busy_timeout=1000")
                conn.execute("SELECT scan_id, tenant_id FROM graph_snapshots LIMIT 0")
                conn.execute("SELECT id, tenant_id FROM graph_nodes LIMIT 0")
                conn.execute("SELECT source_id, target_id, tenant_id FROM graph_edges LIMIT 0")
                conn.execute("SELECT node_id, tenant_id FROM graph_node_search LIMIT 0")
        except (sqlite3.Error, OSError):
            invalidate_read_schema(self._db_path)
            raise

    def _open_ro_conn(self, *, initialize_missing: bool = False) -> sqlite3.Connection | None:
        if not self._db_path.exists():
            if not initialize_missing:
                return None
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            # Create the empty file, then use the same per-file initialization
            # lock/cache as ordinary reads. A connection context does not close.
            sqlite3.connect(str(self._db_path), timeout=1).close()
        ensure_read_schema(self._db_path, self._open_rw_conn, sqlite_graph_store.refresh_query_planner_stats)
        try:
            conn = sqlite3.connect(f"{self._db_path.resolve().as_uri()}?mode=ro", uri=True, timeout=10)
        except sqlite3.OperationalError:
            # Fall back to a normal connection if the platform/filesystem cannot
            # honor the read-only URI (e.g. missing WAL sidecar write access).
            conn = sqlite3.connect(str(self._db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _search_query_expression(query: str) -> str:
        tokens = [token.strip() for token in re.findall(r"[A-Za-z0-9_.:-]+", query) if token.strip()]
        if not tokens:
            return ""
        escaped = [token.replace('"', '""') for token in tokens]
        return " AND ".join(f'"{token}"*' for token in escaped)

    @staticmethod
    def _should_use_fts(query: str) -> bool:
        return any(char.isalnum() for char in query)

    @staticmethod
    def _matches_compliance_prefixes(node: UnifiedNode, prefixes: set[str]) -> bool:
        if not prefixes:
            return True
        node_prefixes = {tag.split("-")[0].upper() if "-" in tag else tag.upper() for tag in node.compliance_tags}
        return bool(node_prefixes.intersection(prefixes))

    @staticmethod
    def _space_token_filter(column: str, token: str) -> tuple[str, list[Any]]:
        escaped = _escape_like_query(token.lower())
        clause = f"({column} = ? OR {column} LIKE ? ESCAPE '\\' OR {column} LIKE ? ESCAPE '\\' OR {column} LIKE ? ESCAPE '\\')"
        params = [escaped, f"{escaped} %", f"% {escaped}", f"% {escaped} %"]
        return clause, params

    @staticmethod
    def _compliance_prefix_filter(column: str, prefix: str) -> tuple[str, list[Any]]:
        escaped = _escape_like_query(prefix.lower())
        clause = (
            f"({column} = ? OR {column} LIKE ? ESCAPE '\\' OR "
            f"{column} LIKE ? ESCAPE '\\' OR {column} LIKE ? ESCAPE '\\' OR {column} LIKE ? ESCAPE '\\')"
        )
        params = [escaped, f"{escaped}-%", f"{escaped} %", f"% {escaped}-%", f"% {escaped} %"]
        return clause, params

    def resolve_node_aliases(self, *, tenant_id: str = "", node_ids: Iterable[str], scan_id: str = "") -> dict[str, str]:
        """Map node ids that canonicalization replaced to their canonical id, within one tenant and snapshot."""
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_ro_conn()
        if conn is None:
            return {}
        try:
            return resolve_node_aliases(conn, tenant_id=tenant_id, node_ids=node_ids, scan_id=scan_id)
        finally:
            conn.close()

    def delete_tenant(self, *, tenant_id: str = "") -> int:
        """Delete graph rows for one tenant and return the number of rows removed."""
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        with self._write_conn() as conn:
            total = 0
            for table in (
                "graph_node_search",
                "graph_attack_paths",
                "attack_paths",
                "interaction_risks",
                "graph_edges",
                "graph_nodes",
                "graph_snapshots",
                "graph_filter_presets",
                "graph_node_aliases",
            ):
                cursor = conn.execute(f"DELETE FROM {table} WHERE tenant_id = ?", (tenant_id,))  # nosec B608 - table list is static
                total += max(cursor.rowcount, 0)
            conn.commit()
            return total

    def delete_snapshot(self, *, tenant_id: str, scan_id: str, expected_generation: str | None = None) -> int:
        """Atomically remove one tenant-scoped snapshot and all projections."""
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        with self._write_conn() as conn:
            # Serialize the ownership check with every SQLite writer, including
            # other processes. Never authorize deletion from a stale read.
            conn.execute("BEGIN IMMEDIATE")
            if expected_generation is not None:
                row = conn.execute(
                    "SELECT snapshot_generation FROM graph_snapshots WHERE tenant_id = ? AND scan_id = ?",
                    (tenant_id, scan_id),
                ).fetchone()
                if not expected_generation or row is None or row[0] != expected_generation:
                    conn.rollback()
                    return 0
            total = 0
            for table in (
                "graph_node_search",
                "graph_attack_paths",
                "attack_paths",
                "interaction_risks",
                "graph_edges",
                "graph_nodes",
                "graph_node_aliases",
                "graph_snapshots",
            ):
                cursor = conn.execute(
                    f"DELETE FROM {table} WHERE tenant_id = ? AND scan_id = ?",  # nosec B608 - table list is static
                    (tenant_id, scan_id),
                )
                total += max(cursor.rowcount, 0)
            conn.commit()
            return total

    _node_from_row = staticmethod(sqlite_node_from_row)
    _edge_from_row = staticmethod(sqlite_edge_from_row)

    @staticmethod
    def _reverse_edge(edge: UnifiedEdge) -> UnifiedEdge:
        return UnifiedEdge(
            source=edge.target,
            target=edge.source,
            relationship=edge.relationship,
            direction=edge.direction,
            weight=edge.weight,
            traversable=edge.traversable,
            first_seen=edge.first_seen,
            last_seen=edge.last_seen,
            valid_from=edge.valid_from,
            valid_to=edge.valid_to,
            confidence=edge.confidence,
            provenance=edge.provenance,
            source_scan_id=edge.source_scan_id,
            source_run_id=edge.source_run_id,
            evidence=edge.evidence,
            activity_id=edge.activity_id,
        )
