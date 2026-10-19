"""Demo workloads are HOSTED_ON the cluster their inventory records."""

from __future__ import annotations

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.types import EntityType, RelationshipType
from tests.test_demo_graph_data_model import demo_graph  # noqa: F401 - pytest fixture


def _edges(graph: UnifiedGraph, relationship: RelationshipType, source: EntityType, target: EntityType) -> list:
    return [
        edge
        for edge in graph.edges
        if edge.relationship == relationship
        and graph.nodes[edge.source].entity_type == source
        and graph.nodes[edge.target].entity_type == target
    ]


def test_every_recorded_workload_cluster_is_a_hosted_on_edge(demo_graph: UnifiedGraph) -> None:  # noqa: F811
    workloads = [
        node
        for node in demo_graph.nodes.values()
        if node.attributes.get("container_kind") == "workload" and node.attributes.get("tags", {}).get("cluster") in demo_graph.nodes
    ]
    hosted = {
        (edge.source, edge.target) for edge in _edges(demo_graph, RelationshipType.HOSTED_ON, EntityType.CONTAINER, EntityType.CLUSTER)
    }

    assert len(workloads) > 100
    assert hosted == {(node.id, node.attributes["tags"]["cluster"]) for node in workloads}
    # The hosting claim is not stored twice under a second relationship.
    assert not _edges(demo_graph, RelationshipType.PART_OF, EntityType.CONTAINER, EntityType.CLUSTER)


def test_images_are_never_hosted_on_a_cluster(demo_graph: UnifiedGraph) -> None:  # noqa: F811
    images = {node.id for node in demo_graph.nodes.values() if node.attributes.get("container_kind") == "image"}
    assert images
    assert not [edge for edge in demo_graph.edges if edge.relationship == RelationshipType.HOSTED_ON and edge.source in images]
