"""Rollup exposure reads the same folded verdict the node's risk context carries."""

from __future__ import annotations

from agent_bom.graph import UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.rollup import rollup_view
from agent_bom.graph.types import EntityType, RelationshipType


def _estate(bucket_attributes: dict) -> UnifiedGraph:
    graph = UnifiedGraph(scan_id="s", tenant_id="t")
    graph.add_node(UnifiedNode(id="account:a", entity_type=EntityType.ACCOUNT, label="a"))
    graph.add_node(UnifiedNode(id="bucket:b", entity_type=EntityType.CLOUD_RESOURCE, label="b", attributes=bucket_attributes))
    graph.add_edge(
        UnifiedEdge(
            source="account:a",
            target="bucket:b",
            relationship=RelationshipType.CONTAINS,
            evidence={"source": "cloud-inventory", "tier": "modeled_infrastructure"},
        )
    )
    return graph


def _aggregate(graph: UnifiedGraph) -> dict:
    [top] = rollup_view(graph)["top_level"]
    return top["aggregate"]


def test_raw_provider_flag_folded_into_risk_context_counts_as_exposed() -> None:
    aggregate = _aggregate(_estate({"publicly_accessible": True, "risk_context": {"internet_exposed": True}}))
    assert aggregate["internet_exposed"] is True
    assert aggregate["exposed_count"] == 1


def test_private_or_unknown_verdict_is_not_exposed() -> None:
    for attributes in ({"risk_context": {"internet_exposed": False}}, {"risk_context": {"internet_exposed": None}}, {}):
        aggregate = _aggregate(_estate(attributes))
        assert aggregate["internet_exposed"] is False
        assert aggregate["exposed_count"] == 0
