"""A LangGraph project reads the same on every surface: report, graph, console.

Uses the ``langgraph_supervisor`` fixture with a pinned manifest written at run
time, scanned through the real CLI.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.types import EntityType, RelationshipType

_FIXTURE = Path(__file__).parent / "fixtures" / "agent_frameworks" / "langgraph_supervisor"


@pytest.fixture(scope="module")
def project(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("lgs") / "proj"
    shutil.copytree(_FIXTURE, root)
    (root / "requirements.txt").write_text("langgraph==0.2.0\n", encoding="utf-8")
    return root


@pytest.fixture(scope="module")
def report(project: Path, tmp_path_factory: pytest.TempPathFactory) -> dict:
    out = tmp_path_factory.mktemp("out") / "report.json"
    args = ["scan", "-p", str(project), "--ai-inventory", str(project), "--offline", "-f", "json", "-o", str(out)]
    result = CliRunner().invoke(main, args)
    assert out.exists(), result.output
    return json.loads(out.read_text(encoding="utf-8"))


def test_framework_links_to_the_manifest_package_not_a_versionless_copy(report: dict) -> None:
    """A CVE on the pinned ``langgraph`` must be reachable from the LangGraph agents via their framework."""
    graph = build_unified_graph_from_report(report)
    framework = next(n for n in graph.nodes_by_type(EntityType.FRAMEWORK) if n.label == "langgraph")
    targets = {
        graph.nodes[e.target].label
        for e in graph.adjacency.get(framework.id, [])
        if e.relationship == RelationshipType.DEPENDS_ON and e.target in graph.nodes
    }

    assert targets == {"langgraph@0.2.0"}
    assert not [n for n in graph.nodes_by_type(EntityType.PACKAGE) if n.attributes.get("from_ai_inventory")]


def test_declared_langgraph_edges_are_not_runtime_observed(report: dict) -> None:
    """A source-declared ``delegated_to`` edge is not recorded runtime activity and must not boost a path."""
    from agent_bom.graph.edge import UnifiedEdge
    from agent_bom.graph.path_derivation import _fusion_signals_for_path

    graph = build_unified_graph_from_report(report)
    langgraph_agents = [n.id for n in graph.nodes_by_type(EntityType.AGENT) if n.attributes.get("agent_type") == "framework-agent"]

    assert langgraph_agents
    for agent_id in langgraph_agents:
        assert "runtime_observed" not in {kind for kind, *_ in _fusion_signals_for_path(graph, [agent_id])}

    search = next(n.id for n in graph.nodes_by_type(EntityType.AGENT) if n.label == "search")
    writer = next(n.id for n in graph.nodes_by_type(EntityType.AGENT) if n.label == "writer")
    observed = UnifiedEdge(source=search, target=writer, relationship=RelationshipType.DELEGATED_TO, evidence={"source": "runtime-trace"})
    graph.add_edge(observed)
    assert "runtime_observed" in {kind for kind, *_ in _fusion_signals_for_path(graph, [search])}
