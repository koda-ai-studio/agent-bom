"""Agent harness model: entry, orchestrator, sub-agents and crews from declared framework topology.

Built from the multi-agent fixture repos (LangGraph supervisor, LangGraph tool
team, CrewAI hierarchical crew). Roles and layers are read from what the source
declares; nothing is invented, and unresolved routes stay on the node.
"""

from __future__ import annotations

from pathlib import Path

from agent_bom.ai_components.framework_agents import scan_framework_agents
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.harness_model import (
    HARNESS_MODEL_VERSION,
    flow_kind,
    placements_from_framework_agents,
)
from agent_bom.graph.types import EntityType

_FIXTURES = Path(__file__).parent / "fixtures" / "agent_frameworks"


def _scan(name: str) -> list[dict]:
    return [agent.to_dict() for agent in scan_framework_agents(_FIXTURES / name)]


def _graph(name: str, scan_id: str = "harness-scan"):
    report = {"agents": [], "ai_inventory": {"framework_agents": _scan(name)}}
    return build_unified_graph_from_report(report, scan_id=scan_id, tenant_id="tenant-a")


def _by_label(graph) -> dict[str, list]:
    out: dict[str, list] = {}
    for node in graph.nodes_by_type(EntityType.AGENT):
        if node.attributes.get("agent_type") == "framework-agent":
            out.setdefault(node.label, []).append(node)
    return out


def _named(agents: list[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for agent in agents:
        out.setdefault(agent["name"], []).append(agent)
    return out


def test_flow_kind_maps_declared_evidence_without_inventing():
    assert flow_kind("delegated_to", "StateGraph.add_edge(START)", "entry", ()) == "entry"
    assert flow_kind("delegated_to", "StateGraph.add_edge(END)", "finish", ()) == "finish"
    assert flow_kind("delegated_to", "StateGraph.add_conditional_edges", "finish", ("__end__",)) == "finish"
    assert flow_kind("delegated_to", "StateGraph.add_conditional_edges", "", ("research",)) == "conditional"
    assert flow_kind("delegated_to", "StateGraph.add_edge", "", ()) == "sequential"
    assert flow_kind("delegated_to", "StateGraph.add_sequence", "", ()) == "sequential"
    assert flow_kind("delegated_to", "Command(goto)", "", ()) == "handoff"
    assert flow_kind("delegated_to", "create_handoff_tool", "", ()) == "handoff"
    assert flow_kind("delegated_to", "create_supervisor(agents)", "", ()) == "handoff"
    assert flow_kind("delegated_to", "Send(node)", "fan_out", ()) == "fan_out"
    assert flow_kind("delegated_to", "StateGraph.add_node(subgraph)", "subgraph", ()) == "subgraph"
    assert flow_kind("delegated_to", "Crew(agents=[...])", "", ()) == "member"
    assert flow_kind("delegated_to", "GroupChat(agents=[...])", "", ()) == "member"
    assert flow_kind("shares_server", "shared Crew membership", "", ()) == "peer"


def test_langgraph_supervisor_layers_roles_and_entry():
    agents = _scan("langgraph_supervisor")
    placements = placements_from_framework_agents(agents)
    named = _named(agents)
    builder = named["builder"][0]["stable_id"]
    by_name = {name: placements[items[0]["stable_id"]] for name, items in named.items() if items[0]["stable_id"] in placements}

    assert by_name["builder"].role == "harness" and by_name["builder"].layer == 0
    assert by_name["supervisor"].role == "orchestrator" and by_name["supervisor"].entry
    assert by_name["supervisor"].layer == 1
    assert by_name["writer"].role == "sub_agent" and by_name["writer"].layer == 1
    # review has one declared handoff target, so it is a sub-agent, not an orchestrator.
    assert by_name["review"].role == "sub_agent"
    assert by_name["research"].role == "sub_agent" and by_name["research"].layer == 1
    # The compiled research graph nests under the research node, one layer down, and its nodes below it.
    assert by_name["research_builder"].role == "subgraph" and by_name["research_builder"].layer == 2
    assert by_name["search"].layer == 3 and by_name["search"].entry
    assert by_name["summarize"].layer == 3
    assert {placement.harness_id for placement in by_name.values()} == {builder}


def test_langgraph_tool_team_nests_workers_with_literal_models():
    agents = _scan("langgraph_tool_team")
    placements = placements_from_framework_agents(agents)
    named = _named(agents)
    builder = named["builder"][0]["stable_id"]
    nodes = [a for a in agents if a["parent_id"] == builder]
    workers = [a for a in agents if a["parent_id"] in {n["stable_id"] for n in nodes}]

    supervisor = next(a for a in nodes if a["name"] == "supervisor")
    assert placements[supervisor["stable_id"]].role == "orchestrator"
    assert placements[supervisor["stable_id"]].entry
    assert {placements[a["stable_id"]].role for a in nodes if a["name"] != "supervisor"} == {"sub_agent"}
    assert {placements[w["stable_id"]].layer for w in workers} == {2}
    assert {placements[w["stable_id"]].role for w in workers} == {"subgraph"}
    assert all(placements[a["stable_id"]].harness_id == builder for a in [*nodes, *workers])


def test_crewai_crew_is_a_harness_of_its_members_and_manager_is_not_invented():
    agents = _scan("crewai_hierarchical")
    placements = placements_from_framework_agents(agents)
    named = _named(agents)
    crew = named["crew"][0]["stable_id"]

    assert placements[crew].role == "harness" and placements[crew].layer == 0
    for worker in ("Evidence Reader", "Report Writer"):
        placement = placements[named[worker][0]["stable_id"]]
        assert (placement.harness_id, placement.role, placement.layer) == (crew, "sub_agent", 1)
    # manager_agent= is not a declared delegation edge yet: no placement is invented for it.
    assert named["Review Manager"][0]["stable_id"] not in placements


def test_no_framework_estate_has_no_placements():
    assert placements_from_framework_agents([]) == {}
    assert placements_from_framework_agents(None) == {}


def test_graph_projection_stamps_harness_attributes_and_keeps_unresolved_routes():
    graph = _graph("langgraph_supervisor")
    nodes = _by_label(graph)
    review = nodes["review"][0].attributes
    assert review["harness_model"] == HARNESS_MODEL_VERSION
    assert review["harness_role"] == "sub_agent"
    assert review["harness_layer"] == 1
    assert review["unresolved_routes"] == [
        {"evidence": "StateGraph.add_conditional_edges(decide)", "line_number": 57, "reason": "no path map; targets decided at runtime"}
    ]
    builder = nodes["builder"][0]
    assert builder.attributes["harness_role"] == "harness"
    assert builder.attributes["harness_id"] == builder.id
    assert nodes["supervisor"][0].attributes["harness_entry"] is True


def test_harness_ids_and_placements_are_stable_across_rescans():
    def snapshot(scan_id: str) -> dict[str, tuple]:
        graph = _graph("langgraph_tool_team", scan_id)
        return {
            node.id: (node.attributes["harness_id"], node.attributes["harness_role"], node.attributes["harness_layer"])
            for node in graph.nodes_by_type(EntityType.AGENT)
            if node.attributes.get("harness_model")
        }

    first, second = snapshot("scan-1"), snapshot("scan-2")
    assert first and first == second
