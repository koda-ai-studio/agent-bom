"""A graph saved by the CLI writer (``scan --context-graph``) is searchable by the API store."""

from __future__ import annotations

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.db import graph_store as cli_store
from agent_bom.graph import EntityType, UnifiedGraph, UnifiedNode


def _graph(scan: str, label: str) -> UnifiedGraph:
    graph = UnifiedGraph(tenant_id="tenant-cli", scan_id=scan)
    graph.add_node(UnifiedNode(id="agent:cli", entity_type=EntityType.AGENT, label=label))
    graph.add_node(UnifiedNode(id="pkg:other", entity_type=EntityType.PACKAGE, label="unrelated"))
    return graph


def test_cli_saved_graph_populates_search_index(tmp_path):
    path = tmp_path / "graph.db"
    with cli_store.open_graph_db(path) as conn:
        cli_store.save_graph(conn, _graph("scan-1", "needle agent"))

    nodes, total, _cursor = SQLiteGraphStore(path).search_nodes(tenant_id="tenant-cli", scan_id="scan-1", query="needle")
    assert total == 1
    assert [node.id for node in nodes] == ["agent:cli"]


def test_cli_resave_replaces_search_rows(tmp_path):
    path = tmp_path / "graph.db"
    with cli_store.open_graph_db(path) as conn:
        cli_store.save_graph(conn, _graph("scan-1", "needle agent"))
    with cli_store.open_graph_db(path) as conn:
        cli_store.save_graph(conn, _graph("scan-1", "haystack agent"))

    store = SQLiteGraphStore(path)
    assert store.search_nodes(tenant_id="tenant-cli", scan_id="scan-1", query="needle")[1] == 0
    assert store.search_nodes(tenant_id="tenant-cli", scan_id="scan-1", query="haystack")[1] == 1


def test_api_store_search_rows_are_not_duplicated(tmp_path):
    import sqlite3

    path = tmp_path / "graph.db"
    SQLiteGraphStore(path).save_graph(_graph("scan-1", "needle agent"))
    with sqlite3.connect(path) as conn:
        rows = conn.execute("SELECT COUNT(*) FROM graph_node_search WHERE scan_id = 'scan-1'").fetchone()[0]
    assert rows == 2
