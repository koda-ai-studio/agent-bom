"""Correlation and re-keying keep relationship-level facts: credential ownership and per-edge paths."""

from __future__ import annotations

import pytest

from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.container import AttackPath, UnifiedGraph
from agent_bom.graph.correlation import CorrelationSnapshot, merge_graph_snapshots
from agent_bom.graph.correlation_workspace import CorrelationMergeWorkspace
from agent_bom.graph.credential_reach import credential_routes
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.store_backed import open_store_backed_unified_graph
from agent_bom.graph.types import EntityType, RelationshipType


def _agent_ids(graph) -> list[str]:
    return [node.id for node in graph.nodes_by_type(EntityType.AGENT)]


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_correlation_remaps_credential_ownership_when_agent_ids_change(backend):
    graphs = []
    for environment in ["prod", "stage"]:
        graph = build_unified_graph_from_report(
            {
                "agents": [
                    {
                        "name": "assistant",
                        "type": "custom",
                        "environment": environment,
                        "mcp_servers": [
                            {
                                "name": "docs",
                                "transport": "sse",
                                "url": "https://mcp.example.test/sse",
                                "credential_env_vars": ["DOCS_TOKEN"],
                            }
                        ],
                    }
                ]
            },
            tenant_id="t",
            scan_id=environment,
        )
        agents = _agent_ids(graph)
        assert len(agents) == 1
        assert all(credential_routes(graph, agents, analyzer="audit").values())
        graphs.append(graph)
    snapshots = [CorrelationSnapshot.from_graph(graph) for graph in graphs]
    if backend == "memory":
        merged = merge_graph_snapshots(correlation_id="merged", tenant_id="t", snapshots=snapshots).graph
        agents = _agent_ids(merged)
        assert len(agents) == 2
        assert all(credential_routes(merged, agents, analyzer="audit").values())
        return
    with CorrelationMergeWorkspace(
        correlation_id="merged",
        tenant_id="t",
        created_at="2026-10-15T00:00:00Z",
        max_output_nodes=100,
        max_output_edges=100,
    ) as workspace:
        for snapshot in snapshots:
            workspace.add_snapshot(snapshot)
        merged = workspace.finish().graph
        agents = _agent_ids(merged)
        assert len(agents) == 2
        assert all(credential_routes(merged, agents, analyzer="audit").values())


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_rekey_preserves_paths_with_distinct_relationships(backend):
    graph = (
        UnifiedGraph()
        if backend == "memory"
        else open_store_backed_unified_graph(backend="sqlite", tenant_id="audit", capacity=2, page_size=2)
    )
    for identifier, kind in [
        ("role:reader", EntityType.ROLE),
        ("data:records", EntityType.DATA_STORE),
        ("resource:old", EntityType.CLOUD_RESOURCE),
    ]:
        graph.add_node(UnifiedNode(id=identifier, entity_type=kind, label=identifier))
    for relationship in [RelationshipType.HAS_PERMISSION, RelationshipType.CAN_ACCESS]:
        graph.add_edge(UnifiedEdge(source="role:reader", target="data:records", relationship=relationship))
        graph.attack_paths.append(
            AttackPath(
                source="role:reader",
                target="data:records",
                hops=["role:reader", "data:records"],
                edges=[relationship.value],
                composite_risk=5.0,
            )
        )
    assert len(graph.attack_paths) == 2
    assert len(graph.edges) == 2
    graph.rekey_nodes({"resource:old": "resource:new"})
    assert len(graph.attack_paths) == 2
