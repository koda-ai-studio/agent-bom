"""LangGraph prebuilt multi-agent shapes: supervisor, swarm, handoff tools, ToolNode, model bindings.

The sources mirror the published quick-start shapes of ``langgraph-supervisor``
and ``langgraph-swarm`` (synthetic names, nothing runs).
"""

from __future__ import annotations

from pathlib import Path

from agent_bom.ai_components.framework_agents import scan_framework_agents

_SUPERVISOR = """
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from langgraph_supervisor import create_supervisor

model = ChatOpenAI(model="gpt-4o")

def add(a, b):
    return a + b

def web_search(query):
    return ""

math_agent = create_react_agent(model=model, tools=[add], name="math_expert")
research_agent = create_react_agent(model=model, tools=[web_search], name="research_expert")
workflow = create_supervisor([research_agent, math_agent], model=model, prompt="route")
app = workflow.compile()
"""

_NESTED_SUPERVISOR = """
from langgraph.prebuilt import create_react_agent
from langgraph_supervisor import create_supervisor

a = create_react_agent("openai:gpt-4o", [], name="a")
b = create_react_agent("openai:gpt-4o", [], name="b")
team = create_supervisor([a, b], model="openai:gpt-4o", supervisor_name="team_lead").compile(name="team")
top = create_supervisor(agents=[team], model="openai:gpt-4o", supervisor_name="top_level")
"""

_SWARM = """
from langchain.agents import create_agent
from langchain.chat_models import init_chat_model
from langgraph_swarm import create_handoff_tool, create_swarm

model = init_chat_model(model="gpt-4o", model_provider="openai")

def book_flight(flight_id):
    return "ok"

def book_hotel(hotel_id):
    return "ok"

to_hotel = create_handoff_tool(agent_name="hotel_assistant", description="hotels")
to_flight = create_handoff_tool(agent_name="flight_assistant")

flight = create_agent(model, tools=[book_flight, to_hotel], name="flight_assistant")
hotel = create_agent(model, tools=[book_hotel, to_flight], name="hotel_assistant")
swarm = create_swarm([flight, hotel], default_active_agent="flight_assistant")
app = swarm.compile()
"""

_TOOL_NODE = """
from langgraph.graph import StateGraph
from langgraph.prebuilt import ToolNode

def search(query):
    return ""

def fetch(url):
    return ""

TOOLS = [search, fetch]

def call_model(state):
    return state

builder = StateGraph(dict)
builder.add_node(call_model)
builder.add_node("tools", ToolNode(TOOLS))
builder.add_edge("__start__", "call_model")
builder.add_edge("tools", "call_model")
"""


def _scan(tmp_path: Path, source: str) -> dict[str, dict]:
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    agents = [agent.to_dict() for agent in scan_framework_agents(tmp_path)]
    by_name = {agent["name"]: agent for agent in agents}
    assert len(by_name) == len(agents), [agent["name"] for agent in agents]
    return by_name


def _edges(agent: dict) -> set[tuple[str, str, str]]:
    return {(e["target_name"], e["evidence"], e["kind"]) for e in agent["topology_edges"]}


def test_supervisor_delegates_to_its_members_and_they_hand_back(tmp_path: Path) -> None:
    agents = _scan(tmp_path, _SUPERVISOR)

    supervisor = agents["workflow"]
    assert supervisor["framework"] == "langgraph"
    assert _edges(supervisor) == {
        ("research_expert", "create_supervisor(agents)", ""),
        ("math_expert", "create_supervisor(agents)", ""),
    }
    for member in ("math_expert", "research_expert"):
        assert agents[member]["parent_id"] == supervisor["stable_id"]
        assert ("workflow", "create_supervisor(handoff back)", "") in _edges(agents[member])
    assert all(e["provenance"] == "declared" for e in supervisor["topology_edges"])


def test_model_passed_through_a_binding_is_recorded(tmp_path: Path) -> None:
    agents = _scan(tmp_path, _SUPERVISOR)

    assert agents["workflow"]["model_refs"] == ["gpt-4o"]
    assert agents["math_expert"]["model_refs"] == ["gpt-4o"]
    assert [c["name"] for c in agents["math_expert"]["capabilities"]] == ["add"]


def test_nested_supervisors_keep_their_names_and_nesting(tmp_path: Path) -> None:
    agents = _scan(tmp_path, _NESTED_SUPERVISOR)

    assert {"a", "b", "team", "top_level"} <= set(agents)
    assert _edges(agents["top_level"]) == {("team", "create_supervisor(agents)", "")}
    assert agents["team"]["parent_id"] == agents["top_level"]["stable_id"]
    assert agents["a"]["parent_id"] == agents["team"]["stable_id"]
    assert agents["top_level"]["model_refs"] == ["openai:gpt-4o"]


def test_swarm_enters_at_the_default_agent_and_handoff_tools_link_members(tmp_path: Path) -> None:
    agents = _scan(tmp_path, _SWARM)

    swarm, flight, hotel = agents["swarm"], agents["flight_assistant"], agents["hotel_assistant"]
    assert swarm["framework"] == "langgraph"
    assert _edges(swarm) == {
        ("flight_assistant", "create_swarm(default_active_agent)", "entry"),
        ("hotel_assistant", "create_swarm(active_agent)", "entry"),
    }
    assert flight["parent_id"] == hotel["parent_id"] == swarm["stable_id"]
    assert ("hotel_assistant", "create_handoff_tool", "") in _edges(flight)
    assert ("flight_assistant", "create_handoff_tool", "") in _edges(hotel)
    assert flight["model_refs"] == ["gpt-4o"]
    assert {c["name"] for c in flight["capabilities"]} == {"book_flight", "to_hotel"}


def test_unresolved_handoff_target_is_recorded_not_dropped(tmp_path: Path) -> None:
    source = _SWARM.replace('agent_name="hotel_assistant"', 'agent_name="concierge"')
    agents = _scan(tmp_path, source)

    flight = agents["flight_assistant"]
    assert flight["dynamic_edges"] is True
    assert [r["reason"] for r in flight["unresolved_routes"]] == ["handoff target 'concierge' is not an agent in this file"]


def test_tool_node_lists_the_tools_it_executes(tmp_path: Path) -> None:
    agents = _scan(tmp_path, _TOOL_NODE)

    assert [c["name"] for c in agents["tools"]["capabilities"]] == ["search", "fetch"]
    assert agents["call_model"]["capabilities"] == []
