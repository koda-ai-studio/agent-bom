"""Shared MCP endpoints must not fan out into a quadratic agent-pair mesh."""

from __future__ import annotations

import time

from agent_bom.graph import build_unified_graph_from_report
from agent_bom.graph.blast_projection import MAX_PAIRWISE_SHARED_AGENTS
from agent_bom.graph.types import EntityType, RelationshipType


def _report(agent_count: int) -> dict:
    agents = []
    for i in range(agent_count):
        agents.append(
            {
                "name": f"agent-{i:05d}",
                "agent_type": "cursor",
                "source": "local",
                "config_path": f"/home/u{i}/.cursor/mcp.json",
                "status": "configured",
                "mcp_servers": [
                    {
                        "name": "remote",
                        "url": "https://mcp.example.com/sse",
                        "transport": "sse",
                        "tools": [{"name": "search", "description": ""}],
                        "packages": [],
                    }
                ],
            }
        )
    return {"scan_id": "s", "agents": agents, "blast_radius": []}


def _shared_server(graph):
    servers = [n for n in graph.nodes.values() if n.entity_type == EntityType.SERVER]
    assert len(servers) == 1
    return servers[0]


def _shares(graph):
    return [e for e in graph.edges if e.relationship == RelationshipType.SHARES_SERVER]


def test_small_share_group_keeps_pairwise_edges_and_count() -> None:
    graph = build_unified_graph_from_report(_report(3), scan_id="s", tenant_id="default")
    assert len(_shares(graph)) == 3
    server = _shared_server(graph)
    assert server.attributes["shared_agent_count"] == 3
    assert server.attributes["shares_server_pairwise"] is True


def test_single_agent_server_has_no_share_attributes() -> None:
    graph = build_unified_graph_from_report(_report(1), scan_id="s", tenant_id="default")
    assert _shares(graph) == []
    assert "shared_agent_count" not in _shared_server(graph).attributes


def test_large_share_group_is_linear_and_counted_on_server() -> None:
    k = 2_000
    started = time.perf_counter()
    graph = build_unified_graph_from_report(_report(k), scan_id="s", tenant_id="default")
    elapsed = time.perf_counter() - started

    assert _shares(graph) == []
    server = _shared_server(graph)
    assert server.attributes["shared_agent_count"] == k
    assert server.attributes["shares_server_pairwise"] is False
    uses = [e for e in graph.edges if e.relationship == RelationshipType.USES and e.target == server.id]
    assert len(uses) == k
    # O(k): a handful of edges per agent (uses, tool, ...), never k^2/2 (~2M).
    assert len(graph.edges) <= 10 * k
    assert elapsed < 20.0


def test_cap_boundary() -> None:
    at_cap = build_unified_graph_from_report(_report(MAX_PAIRWISE_SHARED_AGENTS), scan_id="s", tenant_id="default")
    n = MAX_PAIRWISE_SHARED_AGENTS
    assert len(_shares(at_cap)) == n * (n - 1) // 2
    over = build_unified_graph_from_report(_report(n + 1), scan_id="s", tenant_id="default")
    assert _shares(over) == []
    assert _shared_server(over).attributes["shared_agent_count"] == n + 1
