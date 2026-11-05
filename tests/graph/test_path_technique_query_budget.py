"""Technique enrichment reuses the batch hop index on storage-backed graphs."""

from agent_bom.graph.container import AttackPath
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.path_evidence import with_technique_mappings
from agent_bom.graph.store_backed import open_store_backed_unified_graph
from agent_bom.graph.types import EntityType, RelationshipType


def test_shared_source_adjacency_is_read_once_for_batch(monkeypatch):
    with open_store_backed_unified_graph(tenant_id="one", scan_id="fixture", backend="sqlite") as graph:
        graph.add_node(UnifiedNode(id="server", entity_type=EntityType.SERVER, label="server"))
        paths = []
        for index in range(40):
            target = f"package:{index}"
            graph.add_node(UnifiedNode(id=target, entity_type=EntityType.PACKAGE, label=target))
            graph.add_edge(UnifiedEdge(source="server", target=target, relationship=RelationshipType.DEPENDS_ON))
            paths.append(
                AttackPath(
                    source="server", target=target, hops=["server", target], edges=["depends_on"], composite_risk=1, summary="fixture"
                )
            )
        reads = []
        original = graph._adjacency

        def counted(node_id):
            reads.append(node_id)
            return original(node_id)

        monkeypatch.setattr(graph, "_adjacency", counted)
        annotated = with_technique_mappings(paths, graph)
        assert reads == ["server"]
        assert len(annotated) == 40
        assert all(len(path.hop_evidence) == 1 for path in annotated)
        assert all(path.technique_mappings == [] for path in annotated)


def test_batch_index_preserves_source_backed_technique_mapping():
    from agent_bom.graph.attack_path_fusion import compute_fused_attack_paths
    from agent_bom.graph.attack_path_mitre import derive_attack_path_techniques
    from tests.test_attack_path_mitre import _kill_chain_graph

    graph = _kill_chain_graph()
    path = compute_fused_attack_paths(graph)[0]
    expected = derive_attack_path_techniques(path, graph)
    assert [mapping.technique_id for mapping in expected] == ["T1530"]
    result = with_technique_mappings([path], graph)[0]
    assert result.technique_mappings == expected
