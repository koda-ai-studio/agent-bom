"""An inventory finding path is attributable, bounded and never execution proof."""

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.trace_inventory_paths import attach_inventory_paths
from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode


def test_only_recorded_directed_occurrence_paths_are_attached(tmp_path):
    store = SQLiteGraphStore(str(tmp_path / "graph.db"))
    graph = UnifiedGraph(tenant_id="tenant", scan_id="scan")
    for identity, kind in [
        ("agent", EntityType.AGENT),
        ("server", EntityType.SERVER),
        ("package", EntityType.PACKAGE),
        ("finding", EntityType.VULNERABILITY),
        ("other", EntityType.PACKAGE),
    ]:
        graph.add_node(UnifiedNode(id=identity, entity_type=kind, label=identity))
    for source, target, relationship in [
        ("agent", "server", RelationshipType.USES),
        ("server", "package", RelationshipType.DEPENDS_ON),
        ("package", "finding", RelationshipType.VULNERABLE_TO),
        ("agent", "other", RelationshipType.POSSIBLY_CORRELATES_WITH),
    ]:
        graph.add_edge(UnifiedEdge(source=source, target=target, relationship=relationship))
    store.save_graph(graph)
    generation = store.snapshot_identity(tenant_id="tenant", scan_id="scan")[1]
    bindings = {
        "span": {
            "state": "exact_identifier",
            "node_id": "agent",
            "scan_id": "scan",
            "snapshot_generation": generation,
            "execution_proven": False,
        },
        "unmapped": {"state": "unmapped"},
    }
    result = attach_inventory_paths(store, tenant_id="tenant", scan_id="scan", bindings=bindings)
    path = result["span"]["inventory_paths"][0]
    assert path["node_ids"] == ["agent", "server", "package", "finding"]
    assert len(path["edge_ids"]) == 3
    assert path["basis"] == "recorded_inventory_relationships"
    assert path["execution_proven"] is False
    assert result["unmapped"] == {"state": "unmapped"}
    store.save_graph(UnifiedGraph(tenant_id="tenant", scan_id="scan"))
    assert attach_inventory_paths(store, tenant_id="tenant", scan_id="scan", bindings=bindings)["span"]["state"] == "snapshot_changed"


def test_path_result_cap_is_disclosed():
    from agent_bom.api.trace_inventory_paths import _finding_paths

    graph = UnifiedGraph()
    graph.add_node(UnifiedNode(id="root", entity_type=EntityType.PACKAGE, label="root"))
    for i in range(11):
        graph.add_node(UnifiedNode(id=f"v{i}", entity_type=EntityType.VULNERABILITY, label=f"v{i}"))
        graph.add_edge(UnifiedEdge(source="root", target=f"v{i}", relationship=RelationshipType.VULNERABLE_TO))
    paths, truncated = _finding_paths(graph, "root")
    assert len(paths) == 10
    assert truncated is True
