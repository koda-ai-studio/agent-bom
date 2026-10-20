"""Stored ``hop_count`` counts edges on every persisted path row, matching ``analysis.observed``."""

import sqlite3

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.graph import AttackPath, EntityType, UnifiedGraph, UnifiedNode


def test_sqlite_attack_path_rows_store_edge_counts(tmp_path):
    store = SQLiteGraphStore(str(tmp_path / "graph.db"))
    graph = UnifiedGraph(scan_id="scan-1", tenant_id="t1")
    for name in ("agent:a", "server:s", "pkg:p"):
        graph.add_node(UnifiedNode(id=name, entity_type=EntityType.PACKAGE, label=name))
    graph.attack_paths.append(
        AttackPath(source="agent:a", target="pkg:p", hops=["agent:a", "server:s", "pkg:p"], edges=["uses", "depends_on"])
    )
    store.save_graph(graph)
    with sqlite3.connect(str(tmp_path / "graph.db")) as conn:
        stored = {row[0] for row in conn.execute("SELECT hop_count FROM attack_paths WHERE tenant_id = 't1'")}
        snapshot = {row[0] for row in conn.execute("SELECT hop_count FROM graph_attack_paths WHERE tenant_id = 't1'")}
    assert stored == {2}
    assert snapshot <= {2}
