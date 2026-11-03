"""Passive CrewAI fixture discovery and stable graph evidence across persistence."""

import json
from pathlib import Path

from click.testing import CliRunner

from agent_bom.ai_components.framework_agents import scan_framework_agents
from agent_bom.cli import main
from agent_bom.db.graph_store import load_graph, open_graph_db, save_graph
from agent_bom.graph.builder import build_unified_graph_from_report

FIXTURE = Path(__file__).parent / "fixtures" / "agent_frameworks" / "crewai_hierarchical"


def test_hierarchical_crew_preserves_declared_membership_without_claiming_execution():
    agents = [agent.to_dict() for agent in scan_framework_agents(FIXTURE)]
    assert {agent["name"] for agent in agents} == {"Review Manager", "Evidence Reader", "Report Writer", "crew"}
    assert len(agents) == 4
    assert all(agent["framework"] == "crewai" for agent in agents)
    members = {agent["name"]: agent["topology_edges"] for agent in agents}
    assert any(edge["target_name"] == "Report Writer" and edge["relationship"] == "shares_server" for edge in members["Evidence Reader"])
    assert members["Review Manager"] == []
    assert members["Report Writer"] == []
    assert {edge["target_name"] for edge in members["crew"]} == {"Evidence Reader", "Report Writer"}
    assert all(edge["relationship"] == "delegated_to" for edge in members["crew"])
    assert all(edge["provenance"] == "declared" for agent in agents for edge in agent["topology_edges"])
    assert not list(FIXTURE.glob("requirements*"))


def test_fixture_projects_stable_ids_and_preserves_declared_evidence(tmp_path):
    payload = {"ai_inventory": {"framework_agents": [a.to_dict() for a in scan_framework_agents(FIXTURE)]}, "agents": []}
    first = build_unified_graph_from_report(payload)
    second = build_unified_graph_from_report(payload)
    assert first.nodes
    assert set(first.nodes) == set(second.nodes)
    assert {edge.id for edge in first.edges} == {edge.id for edge in second.edges}
    membership = [edge for edge in first.edges if edge.relationship.value == "shares_server"]
    assert membership
    assert all(edge.evidence for edge in membership)

    first.tenant_id = "fixture-tenant"
    first.scan_id = "crewai-passive"
    with open_graph_db(tmp_path / "graph.db") as conn:
        save_graph(conn, first)
    with open_graph_db(tmp_path / "graph.db") as conn:
        restored = load_graph(conn, tenant_id=first.tenant_id, scan_id=first.scan_id)
        assert set(restored.nodes) == set(first.nodes)
        assert {edge.id: edge.evidence for edge in restored.edges} == {edge.id: edge.evidence for edge in first.edges}
        assert not load_graph(conn, tenant_id="other-tenant", scan_id=first.scan_id).nodes


def test_passive_crew_scan_exports_framework_evidence_without_running_the_fixture(tmp_path):
    output = tmp_path / "report.json"
    result = CliRunner().invoke(main, ["scan", "-p", str(FIXTURE), "--no-discover", "--offline", "-f", "json", "-o", str(output)])
    assert output.exists(), result.output
    report = json.loads(output.read_text())
    discovered = report["ai_inventory"]["framework_agents"]
    assert {agent["name"] for agent in discovered} == {"Review Manager", "Evidence Reader", "Report Writer", "crew"}
    graph = build_unified_graph_from_report(report)
    assert graph.nodes and graph.edges
    assert any(edge.relationship.value == "delegated_to" for edge in graph.edges)
