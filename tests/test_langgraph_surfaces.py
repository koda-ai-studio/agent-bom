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


def _plain(lines: list[str]) -> list[str]:
    from rich.text import Text

    return [Text.from_markup(line).plain.rstrip() for line in "\n".join(lines).splitlines()]


def test_console_topology_reads_as_flows_grouped_by_graph(report: dict) -> None:
    from agent_bom.cli.agents._framework_topology_view import topology_lines

    plain = _plain(topology_lines(report["ai_inventory"]["framework_agents"]))

    assert plain[0] == "  Agent graphs (2 graph(s) · 6 node(s) · 11 route(s) · 1 unresolved)"
    assert plain[1:] == [
        "",
        "    research_builder langgraph · app.py:29 · subgraph of research",
        "      START → search",
        "      search → summarize",
        "      summarize → END",
        "",
        "    builder langgraph · app.py:49",
        "      START → supervisor",
        "      supervisor → research, writer, END",
        "      research → subgraph research_builder, supervisor",
        "      writer → END",
        "      review → writer (goto)",
        "        ? unresolved line 57: no path map; targets decided at runtime",
    ]


def test_console_supervisor_reads_as_delegation_not_entry(tmp_path: Path) -> None:
    from agent_bom.ai_components.framework_agents import scan_framework_agents
    from agent_bom.cli.agents._framework_topology_view import topology_lines

    (tmp_path / "app.py").write_text(
        "from langgraph.prebuilt import create_react_agent\n"
        "from langgraph_supervisor import create_supervisor\n"
        "a = create_react_agent('openai:gpt-4o', [], name='a')\n"
        "b = create_react_agent('openai:gpt-4o', [], name='b')\n"
        "team = create_supervisor([a, b], model='openai:gpt-4o')\n",
        encoding="utf-8",
    )
    plain = _plain(topology_lines([agent.to_dict() for agent in scan_framework_agents(tmp_path)]))

    assert "      team → a, b" in plain
    assert not [line for line in plain if line.strip().startswith("START")]
    assert "      a → team" in plain


def test_console_topology_is_printed_by_the_scan(project: Path) -> None:
    args = ["scan", "-p", str(project), "--ai-inventory", str(project), "--offline", "-f", "console"]
    output = CliRunner().invoke(main, args, terminal_width=200).output

    assert "Agent graphs (2 graph(s)" in output
    assert "supervisor → research, writer, END" in output
