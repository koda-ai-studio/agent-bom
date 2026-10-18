"""Trace order is context, never reachability or data-access evidence."""

from __future__ import annotations

from agent_bom.api.finding_reachability import project_attack_path_reachability
from agent_bom.graph.cnapp_overlay import apply_cnapp_overlay
from agent_bom.graph.container import AttackPath, UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType

_CVE = "CVE-2024-0001"


def _row() -> dict[str, object]:
    return {"id": "finding-1", "cve_id": _CVE, "node_id": "pkg:pypi:demo@1.0"}


def _path(edges: list[str]) -> AttackPath:
    return AttackPath(
        source="agent:a",
        target=f"vuln:{_CVE}",
        hops=["agent:a", "server:s", "pkg:pypi:demo@1.0", f"vuln:{_CVE}"],
        edges=edges,
        vuln_ids=[_CVE],
    )


def test_trace_step_only_route_does_not_mark_finding_reachable() -> None:
    rows = [_row()]
    trace = RelationshipType.TRACE_STEP.value
    stamped = project_attack_path_reachability(rows, [_path([trace, trace, RelationshipType.VULNERABLE_TO.value])])

    assert stamped == 0
    assert rows[0].get("graph_reachable") is None
    assert not rows[0].get("graph_reachable_from_agents")


def test_trace_step_hop_disqualifies_an_otherwise_evidenced_route() -> None:
    rows = [_row()]
    path = _path([RelationshipType.INVOKED.value, RelationshipType.TRACE_STEP.value, RelationshipType.VULNERABLE_TO.value])

    assert project_attack_path_reachability(rows, [path]) == 0
    assert rows[0].get("graph_reachable") is None


def test_runtime_route_without_trace_order_still_marks_reachable() -> None:
    rows = [_row()]
    path = _path([RelationshipType.INVOKED.value, RelationshipType.DEPENDS_ON.value, RelationshipType.VULNERABLE_TO.value])

    assert project_attack_path_reachability(rows, [path]) == 1
    assert rows[0]["graph_reachable"] is True
    assert rows[0]["graph_reachable_from_agents"] == ["agent:a"]


def _sensitive_store_graph(relationship: RelationshipType) -> UnifiedGraph:
    graph = UnifiedGraph(scan_id="s", tenant_id="t")
    graph.add_node(
        UnifiedNode(
            id="cloud:rds-customers",
            entity_type=EntityType.CLOUD_RESOURCE,
            label="customer RDS database",
            attributes={"resource_type": "rds", "tags": {"data_classification": "pii"}},
        )
    )
    graph.add_node(UnifiedNode(id="managed_identity:etl", entity_type=EntityType.MANAGED_IDENTITY, label="etl-role"))
    graph.add_edge(UnifiedEdge(source="managed_identity:etl", target="data_store:cloud:rds-customers", relationship=relationship))
    return graph


def test_trace_step_into_sensitive_store_is_not_data_access() -> None:
    graph = _sensitive_store_graph(RelationshipType.TRACE_STEP)

    stats = apply_cnapp_overlay(graph)

    store = graph.nodes["data_store:cloud:rds-customers"]
    assert store.attributes.get("data_sensitivity") == "sensitive"
    assert "sensitive_data_access_count" not in store.attributes
    assert "sensitive_data_access_subjects" not in store.attributes
    assert stats["sensitive_data_access_paths"] == 0
    assert not any(risk.pattern == "sensitive_data_reachable" for risk in graph.interaction_risks)


def test_permission_edge_into_sensitive_store_is_still_data_access() -> None:
    graph = _sensitive_store_graph(RelationshipType.CAN_ACCESS)

    stats = apply_cnapp_overlay(graph)

    store = graph.nodes["data_store:cloud:rds-customers"]
    assert store.attributes.get("sensitive_data_access_count") == 1
    assert stats["sensitive_data_access_paths"] == 1
