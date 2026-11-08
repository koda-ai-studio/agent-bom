"""Effective reach stays linear in the edge count on large estates.

Scoring walked every graph edge once per vulnerability, server and blast row,
so a 5,000-agent estate spent minutes of CPU per findings read and starved
concurrent graph reads. These tests pin both the linear walk and the result.
"""

from __future__ import annotations

from typing import Any

from agent_bom.context_graph import ContextGraph, build_context_graph
from agent_bom.effective_reach import annotate_graph, occurrence_contexts


class _CountingEdges(list):
    """An edge list that counts full walks."""

    walks = 0

    def __iter__(self) -> Any:
        type(self).walks += 1
        return super().__iter__()


def _estate(agents: int, vulns_per_server: int) -> tuple[list[dict], list[dict]]:
    agent_rows: list[dict] = []
    blast: list[dict] = []
    for index in range(agents):
        name = f"agent-{index}"
        server = {
            "name": f"server-{index % 7}",
            "command": f"node server-{index}.js",
            "transport": "streamable-http" if index % 3 == 0 else "stdio",
            "url": f"https://shared-{index % 4}.example.test/mcp" if index % 3 == 0 else "",
            "env": {"AWS_ACCESS_KEY_ID": "AKIA****"} if index % 2 else {"GITHUB_TOKEN": "ghp_****"},
            "tools": [{"name": "run_shell", "description": "Execute commands", "capabilities": ["execute"]}],
            "packages": [{"name": f"pkg-{index % 11}", "version": "1.0.0"}],
        }
        agent_rows.append({"name": name, "type": "claude", "status": "configured", "mcp_servers": [server]})
        for offset in range(vulns_per_server):
            blast.append(
                {
                    "vulnerability_id": f"CVE-2099-{(index + offset) % 23}",
                    "finding_id": f"finding-{index}-{offset}",
                    "package": f"pkg-{index % 11}",
                    "package_version": "1.0.0",
                    "severity": "high",
                    "cvss_score": 7.5,
                    "epss_score": 0.1,
                    "affected_agents": [name],
                    "affected_servers": [server["name"]],
                }
            )
    return agent_rows, blast


def _counting(graph: ContextGraph) -> ContextGraph:
    _CountingEdges.walks = 0
    graph.edges = _CountingEdges(graph.edges)
    return graph


def test_annotate_graph_walks_edges_a_bounded_number_of_times() -> None:
    agents, blast = _estate(60, 3)
    graph = _counting(build_context_graph(agents, blast))
    vulns = sum(1 for node in graph.nodes.values() if node.kind.value == "vulnerability")
    assert vulns > 10

    annotate_graph(graph)

    assert _CountingEdges.walks <= 3


def test_occurrence_contexts_walk_edges_a_bounded_number_of_times() -> None:
    agents, blast = _estate(60, 3)
    graph = _counting(build_context_graph(agents, blast))

    contexts = occurrence_contexts(graph, blast)

    assert contexts
    assert _CountingEdges.walks <= 3
