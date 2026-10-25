"""A scan of a LangGraph project carries its framework agents into JSON and both graph views."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.types import EntityType, RelationshipType

_FIXTURE = Path(__file__).parent / "fixtures" / "agent_frameworks" / "langgraph_two_nodes"


def _scan(project: Path, out: Path, fmt: str) -> dict:
    result = CliRunner().invoke(main, ["scan", "-p", str(project), "--offline", "-f", fmt, "-o", str(out)])
    assert out.exists(), result.output
    return json.loads(out.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def langgraph_project(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("lg") / "proj"
    shutil.copytree(_FIXTURE, root)
    (root / "requirements.txt").write_text("langgraph==0.2.0\n", encoding="utf-8")
    return root


@pytest.fixture(scope="module")
def json_report(langgraph_project: Path, tmp_path_factory: pytest.TempPathFactory) -> dict:
    return _scan(langgraph_project, tmp_path_factory.mktemp("out") / "report.json", "json")


@pytest.fixture(scope="module")
def cytoscape(langgraph_project: Path, tmp_path_factory: pytest.TempPathFactory) -> dict:
    return _scan(langgraph_project, tmp_path_factory.mktemp("out") / "graph.json", "graph")


def _by_name(framework_agents: list[dict]) -> dict[str, dict]:
    return {agent["name"]: agent for agent in framework_agents}


def test_json_report_carries_framework_agents_and_edges(json_report: dict) -> None:
    agents = _by_name(json_report["ai_inventory"]["framework_agents"])

    assert {"planner", "writer"} <= set(agents)
    edges = agents["planner"]["topology_edges"]
    assert [(e["source_name"], e["target_name"], e["relationship"]) for e in edges] == [("planner", "writer", "delegated_to")]
    assert edges[0]["target_id"] == agents["writer"]["stable_id"]


def test_cytoscape_graph_draws_framework_agents_and_delegation(json_report: dict, cytoscape: dict) -> None:
    agents = _by_name(json_report["ai_inventory"]["framework_agents"])
    elements = cytoscape["elements"]
    nodes = {el["data"]["id"]: el["data"] for el in elements if "source" not in el["data"]}
    edges = {(el["data"]["source"], el["data"]["target"], el["data"]["type"]) for el in elements if "source" in el["data"]}

    planner, writer = agents["planner"]["stable_id"], agents["writer"]["stable_id"]
    assert nodes[planner]["type"] == "agent" and nodes[planner]["label"] == "planner"
    assert nodes[writer]["type"] == "agent" and nodes[writer]["label"] == "writer"
    assert nodes[planner]["agentType"] == "framework-agent"
    assert (planner, writer, "delegated_to") in edges
    framework_ids = {node_id for node_id, data in nodes.items() if data["type"] == "framework"}
    assert framework_ids
    assert any((planner, fid, "uses_framework") in edges for fid in framework_ids)


def test_unified_graph_draws_framework_agents_and_delegation(json_report: dict) -> None:
    agents = _by_name(json_report["ai_inventory"]["framework_agents"])
    graph = build_unified_graph_from_report(json_report)

    planner, writer = agents["planner"]["stable_id"], agents["writer"]["stable_id"]
    assert graph.nodes[planner].entity_type == EntityType.AGENT
    assert graph.nodes[writer].entity_type == EntityType.AGENT
    assert any(
        e.source == planner and e.target == writer and e.relationship == RelationshipType.DELEGATED_TO for e in graph.edges
    )


