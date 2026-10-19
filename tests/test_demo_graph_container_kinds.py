"""Demo images and the workloads running them are distinguishable on the graph."""

from __future__ import annotations

from collections import Counter

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.types import EntityType, RelationshipType
from tests.test_demo_graph_data_model import demo_graph  # noqa: F401 - pytest fixture


def test_estate_images_and_workloads_carry_their_recorded_kind(demo_graph: UnifiedGraph) -> None:  # noqa: F811
    kinds = Counter(
        (node.attributes.get("resource_type"), node.attributes.get("container_kind"))
        for node in demo_graph.nodes.values()
        if node.entity_type == EntityType.CONTAINER and node.attributes.get("estate_id")
    )
    assert kinds[("container_image", "image")] > 100
    assert kinds[("deployment", "workload")] > 100
    assert set(kinds) == {("container_image", "image"), ("deployment", "workload")}


def test_workload_to_image_edges_join_a_workload_to_an_image(demo_graph: UnifiedGraph) -> None:  # noqa: F811
    pairs = [
        (demo_graph.nodes[edge.source].attributes.get("container_kind"), demo_graph.nodes[edge.target].attributes.get("container_kind"))
        for edge in demo_graph.edges
        if edge.relationship == RelationshipType.DEPENDS_ON
        and demo_graph.nodes[edge.source].entity_type == EntityType.CONTAINER
        and demo_graph.nodes[edge.target].entity_type == EntityType.CONTAINER
    ]
    assert len(pairs) > 100
    assert set(pairs) == {("workload", "image")}
