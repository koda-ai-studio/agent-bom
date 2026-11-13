"""graph_edges keeps no index that only repeats an adjacency index's leading columns.

idx_ge_tenant_scan, idx_ge_tenant_scan_source and idx_ge_tenant_scan_target
were left prefixes of idx_ge_adjacency_out / idx_ge_adjacency_in, maintained on
every snapshot write and never needed. Existing stores drop them on open, and
the hot reads still seek on an adjacency index.
"""

from __future__ import annotations

import sqlite3

from agent_bom.db import graph_store
from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedNode

_REDUNDANT = {"idx_ge_tenant_scan", "idx_ge_tenant_scan_source", "idx_ge_tenant_scan_target"}


def _indexes(conn: sqlite3.Connection) -> set[str]:
    return {str(row[1]) for row in conn.execute("PRAGMA index_list(graph_edges)")}


def _open(path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    graph_store._init_db(conn)
    return conn


def _plan(conn: sqlite3.Connection, sql: str, params: tuple) -> str:
    return " | ".join(str(row[3]) for row in conn.execute(f"EXPLAIN QUERY PLAN {sql}", params))


def test_existing_store_drops_the_prefix_indexes_on_open(tmp_path) -> None:
    path = tmp_path / "graph.db"
    conn = _open(path)
    conn.execute("CREATE INDEX idx_ge_tenant_scan ON graph_edges(tenant_id, scan_id)")
    conn.execute("CREATE INDEX idx_ge_tenant_scan_source ON graph_edges(tenant_id, scan_id, source_id)")
    conn.execute("CREATE INDEX idx_ge_tenant_scan_target ON graph_edges(tenant_id, scan_id, target_id)")
    conn.commit()
    assert _REDUNDANT <= _indexes(conn)
    conn.close()
    reopened = _open(path)
    indexes = _indexes(reopened)
    assert not _REDUNDANT & indexes, indexes
    assert {"idx_ge_adjacency_out", "idx_ge_adjacency_in"} <= indexes, indexes


def test_hot_edge_reads_seek_on_an_adjacency_index(tmp_path) -> None:
    conn = _open(tmp_path / "graph.db")
    nodes = [UnifiedNode(id=f"agent:{index}", entity_type=EntityType.AGENT, label=f"Agent {index}") for index in range(4)]
    edges = [UnifiedEdge(source=f"agent:{index}", target=f"agent:{index + 1}", relationship=RelationshipType.USES) for index in range(3)]
    graph_store.save_graph_streaming(conn, scan_id="scan-1", tenant_id="tenant-a", nodes=nodes, edges=edges)
    snapshot = ("tenant-a", "scan-1")
    whole = _plan(
        conn,
        "SELECT * FROM graph_edges WHERE tenant_id = ? AND scan_id = ? ORDER BY source_id, target_id, relationship",
        snapshot,
    )
    assert "idx_ge_adjacency_out" in whole and "TEMP B-TREE" not in whole, whole
    outgoing = _plan(conn, "SELECT * FROM graph_edges WHERE tenant_id = ? AND scan_id = ? AND source_id = ?", (*snapshot, "agent:0"))
    assert "idx_ge_adjacency_out" in outgoing and "source_id=?" in outgoing, outgoing
    incoming = _plan(conn, "SELECT * FROM graph_edges WHERE tenant_id = ? AND scan_id = ? AND target_id = ?", (*snapshot, "agent:1"))
    assert "idx_ge_adjacency_in" in incoming and "target_id=?" in incoming, incoming
    loaded = graph_store.load_graph(conn, tenant_id="tenant-a", scan_id="scan-1", node_budget=2)
    assert len(loaded.nodes) == 2
