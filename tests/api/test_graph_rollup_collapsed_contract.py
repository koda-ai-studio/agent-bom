"""The attack-path roll-up's ``collapsed`` field is a list of rows, and the contract says so."""

from __future__ import annotations

from agent_bom.api.read_models.graph import GraphRollupResponse
from agent_bom.api.server import app
from agent_bom.graph import AttackPath, EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.rollup import attack_path_view


def _graph() -> UnifiedGraph:
    graph = UnifiedGraph(scan_id="s", tenant_id="default")
    for node_id, kind in (("agent:a", EntityType.AGENT), ("server:s", EntityType.SERVER), ("server:other", EntityType.SERVER)):
        graph.add_node(UnifiedNode(id=node_id, entity_type=kind, label=node_id))
    graph.add_edge(UnifiedEdge(source="agent:a", target="server:s", relationship=RelationshipType.USES))
    return graph


_PATHS = [AttackPath(source="agent:a", target="server:s", hops=["agent:a", "server:s"], edges=["uses"])]


def test_attack_path_rollup_validates_with_a_list_of_collapsed_rows():
    payload = attack_path_view(_graph(), _PATHS)

    assert isinstance(payload["collapsed"], list)
    validated = GraphRollupResponse.model_validate({**payload, "completeness": {"status": "complete"}})
    assert validated.collapsed == payload["collapsed"]


def test_openapi_types_collapsed_as_an_array():
    schema = app.openapi()["components"]["schemas"]["GraphRollupResponse"]["properties"]["collapsed"]
    variants = schema.get("anyOf", [schema])
    assert any(variant.get("type") == "array" for variant in variants)
