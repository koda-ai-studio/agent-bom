"""The CNAPP classifier records which carrier established a sensitivity label."""

from __future__ import annotations

from agent_bom.graph.cnapp_overlay import apply_cnapp_overlay
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.risk_context import derive_data_sensitivity
from agent_bom.graph.types import EntityType


def _classify(**node: object) -> dict:
    graph = UnifiedGraph(scan_id="s", tenant_id="t")
    graph.add_node(UnifiedNode(id="ds", entity_type=EntityType.DATA_STORE, **node))  # type: ignore[arg-type]
    apply_cnapp_overlay(graph)
    return graph.nodes["ds"].attributes


def test_name_only_match_is_recorded_as_name() -> None:
    attributes = _classify(label="customer-pii-exports")
    assert attributes["data_sensitivity"] == "sensitive"
    assert attributes["data_sensitivity_basis"] == ["name"]
    _, reasons = derive_data_sensitivity(attributes)
    assert reasons[0]["evidence"] == {"basis": ["name"]}


def test_tag_match_is_recorded_as_metadata() -> None:
    attributes = _classify(label="exports", attributes={"tags": {"classification": "pii"}})
    assert attributes["data_sensitivity_basis"] == ["metadata"]


def test_unclassified_store_records_no_basis() -> None:
    attributes = _classify(label="exports")
    assert "data_sensitivity" not in attributes
    assert "data_sensitivity_basis" not in attributes
