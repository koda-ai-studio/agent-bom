"""Small multi-agent example repos: agents, tools and relationships, end to end.

Each fixture is copied to a temporary project, given a pinned manifest at run
time (fixtures never commit one, see ``tests/fixtures/agent_frameworks/README.md``)
and scanned through the real CLI. The provider key is assembled at run time and
must never reach the report: the scanner records env-var names, not values.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_bom.ai_components.framework_agents import scan_framework_agents
from agent_bom.cli import main
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.types import EntityType, RelationshipType

_FIXTURES = Path(__file__).parent / "fixtures" / "agent_frameworks"
_LANGGRAPH = _FIXTURES / "langgraph_tool_team"
_CREWAI = _FIXTURES / "crewai_hierarchical"
_LANGGRAPH_PINS = "langgraph==1.2.18\nlangchain==1.4.7\n"
_CREWAI_PINS = "crewai==1.15.30\n"
_FAKE_KEY = "-".join(("fixture", "only", "a1b2c3d4e5f6a7b8"))


def _by_name(root: Path) -> dict[str, dict]:
    agents = [agent.to_dict() for agent in scan_framework_agents(root)]
    by_name = {agent["name"]: agent for agent in agents}
    assert len(by_name) == len(agents), "fixture agent names must be unique"
    return by_name


def _tools(agent: dict) -> set[str]:
    return {capability["name"] for capability in agent["capabilities"]}


def _edges(agent: dict) -> set[tuple[str, str]]:
    return {(edge["target_name"], edge["relationship"]) for edge in agent["topology_edges"]}


def _project(tmp_path_factory: pytest.TempPathFactory, fixture: Path, pins: str) -> Path:
    root = tmp_path_factory.mktemp(fixture.name) / "proj"
    shutil.copytree(fixture, root)
    (root / "requirements.txt").write_text(pins, encoding="utf-8")
    return root


def _scan(root: Path, out_dir: Path) -> tuple[dict, str]:
    out = out_dir / "report.json"
    args = ["scan", "-p", str(root), "--ai-inventory", str(root), "--offline", "-f", "json", "-o", str(out)]
    result = CliRunner().invoke(main, args)
    assert out.exists(), result.output
    raw = out.read_text(encoding="utf-8")
    return json.loads(raw), raw


@pytest.fixture(scope="module")
def scanned(tmp_path_factory: pytest.TempPathFactory) -> dict[str, tuple[dict, str]]:
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("OPENAI_API_KEY", _FAKE_KEY)
        return {
            "langgraph": _scan(_project(tmp_path_factory, _LANGGRAPH, _LANGGRAPH_PINS), tmp_path_factory.mktemp("lg-out")),
            "crewai": _scan(_project(tmp_path_factory, _CREWAI, _CREWAI_PINS), tmp_path_factory.mktemp("crew-out")),
        }


def _framework_packages(report: dict, framework: str) -> set[str]:
    graph = build_unified_graph_from_report(report)
    node = next(n for n in graph.nodes_by_type(EntityType.FRAMEWORK) if n.label == framework)
    return {
        graph.nodes[e.target].label
        for e in graph.adjacency.get(node.id, [])
        if e.relationship == RelationshipType.DEPENDS_ON and e.target in graph.nodes
    }


# ── LangGraph: supervisor routing to two tool-using workers ─────────────────


def _langgraph_team() -> tuple[dict, dict[str, dict], dict[str, dict]]:
    """Split the scan into the graph, its nodes, and the ``create_agent`` workers nested under them.

    ``add_node("triage_agent", triage_agent)`` is a graph node that wraps the
    compiled worker of the same name, so each name appears twice with distinct
    ids: once as the node (parent: the graph) and once as the worker (parent: the node).
    """
    agents = [agent.to_dict() for agent in scan_framework_agents(_LANGGRAPH)]
    assert len({agent["stable_id"] for agent in agents}) == len(agents)
    graph = next(agent for agent in agents if agent["name"] == "builder")
    nodes = {agent["name"]: agent for agent in agents if agent["parent_id"] == graph["stable_id"]}
    node_ids = {node["stable_id"] for node in nodes.values()}
    workers = {agent["name"]: agent for agent in agents if agent["parent_id"] in node_ids}
    assert len(agents) == 1 + len(nodes) + len(workers)
    return graph, nodes, workers


def test_langgraph_team_discovers_supervisor_and_tool_workers():
    graph, nodes, workers = _langgraph_team()

    assert set(nodes) == {"supervisor", "triage_agent", "reply_agent"}
    assert set(workers) == {"triage_agent", "reply_agent"}
    assert all(agent["framework"] == "langgraph" for agent in [graph, *nodes.values(), *workers.values()])
    assert _tools(workers["triage_agent"]) == {"lookup_ticket"}
    assert _tools(workers["reply_agent"]) == {"draft_reply"}
    assert _tools(nodes["supervisor"]) == set()
    for worker in workers.values():
        assert worker["model_refs"] == ["openai:gpt-4o-mini"]
        assert worker["credential_refs"] == ["OPENAI_API_KEY"]


def test_langgraph_team_declares_supervisor_routes_and_returns():
    graph, nodes, workers = _langgraph_team()

    assert _edges(graph) == {("supervisor", "delegated_to")}
    assert {("triage_agent", "delegated_to"), ("reply_agent", "delegated_to")} <= _edges(nodes["supervisor"])
    for name, worker in workers.items():
        assert ("supervisor", "delegated_to") in _edges(nodes[name])
        nested = [e for e in nodes[name]["topology_edges"] if e["evidence"] == "StateGraph.add_node(subgraph)"]
        assert [e["target_id"] for e in nested] == [worker["stable_id"]]
    everything = [graph, *nodes.values(), *workers.values()]
    assert all(edge["provenance"] == "declared" for agent in everything for edge in agent["topology_edges"])


# ── CrewAI: hierarchical crew with a manager and two tool-using workers ─────


def test_crewai_crew_discovers_manager_workers_and_their_tools():
    agents = _by_name(_CREWAI)

    assert set(agents) == {"Review Manager", "Evidence Reader", "Report Writer", "crew"}
    assert all(agent["framework"] == "crewai" for agent in agents.values())
    assert _tools(agents["Evidence Reader"]) == {"read_evidence"}
    assert _tools(agents["Report Writer"]) == {"format_report"}
    assert _tools(agents["Review Manager"]) == set()


def test_crewai_crew_links_only_the_listed_workers():
    agents = _by_name(_CREWAI)

    assert ("Report Writer", "shares_server") in _edges(agents["Evidence Reader"])
    assert _edges(agents["crew"]) == {("Evidence Reader", "delegated_to"), ("Report Writer", "delegated_to")}
    assert not any(edge["target_name"] == "Review Manager" for agent in agents.values() for edge in agent["topology_edges"])


# ── Both repos through the CLI with a pinned manifest ───────────────────────


@pytest.mark.parametrize(
    ("framework", "names", "pinned"),
    [
        ("langgraph", {"supervisor", "triage_agent", "reply_agent"}, "langgraph@1.2.18"),
        ("crewai", {"Review Manager", "Evidence Reader", "Report Writer", "crew"}, "crewai@1.15.30"),
    ],
)
def test_cli_report_links_agents_to_the_pinned_framework(scanned, framework: str, names: set[str], pinned: str):
    report, _ = scanned[framework]

    discovered = {agent["name"] for agent in report["ai_inventory"]["framework_agents"] if agent["framework"] == framework}
    assert names <= discovered
    assert _framework_packages(report, framework) == {pinned}


@pytest.mark.parametrize("framework", ["langgraph", "crewai"])
def test_cli_graph_carries_tool_and_relationship_edges(scanned, framework: str):
    report, _ = scanned[framework]
    graph = build_unified_graph_from_report(report)
    agent_ids = {n.id for n in graph.nodes_by_type(EntityType.AGENT) if n.attributes.get("agent_type") == "framework-agent"}
    relationships = {e.relationship for e in graph.edges if e.source in agent_ids and e.target in agent_ids}

    assert RelationshipType.DELEGATED_TO in relationships
    tools = {cap["name"] for agent_id in agent_ids for cap in graph.nodes[agent_id].attributes.get("capabilities") or []}
    expected = {"lookup_ticket", "draft_reply"} if framework == "langgraph" else {"read_evidence", "format_report"}
    assert expected <= tools


def test_runtime_provider_key_never_reaches_the_report(scanned):
    for _, raw in scanned.values():
        assert _FAKE_KEY not in raw
    report, _ = scanned["langgraph"]
    triage = next(a for a in report["ai_inventory"]["framework_agents"] if a["name"] == "triage_agent")
    assert triage["credential_refs"] == ["OPENAI_API_KEY"]


def test_fixtures_commit_no_manifest_or_secret_value():
    for fixture in (_LANGGRAPH, _CREWAI):
        assert not [p.name for p in fixture.iterdir() if p.name.startswith(("requirements", "pyproject", "poetry", "uv.lock", ".env"))]
        for source in fixture.glob("*.py"):
            assert "sk-" not in source.read_text(encoding="utf-8")
