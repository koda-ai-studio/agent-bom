"""LangGraph topology: entry/finish points, conditional routes, subgraphs, handoffs and unresolved routes.

Each test maps to one acceptance criterion of the LangGraph topology issue. The
``langgraph_supervisor`` fixture exercises every construct in one small project;
the inline cases isolate single API shapes so a regression names the construct.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from agent_bom.ai_components import scan_source
from agent_bom.ai_components.framework_agents import scan_framework_agents
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.types import RelationshipType

_FIXTURE = Path(__file__).parent / "fixtures" / "agent_frameworks" / "langgraph_supervisor"


def _payloads(root: Path) -> dict[str, dict]:
    agents = [agent.to_dict() for agent in scan_framework_agents(root)]
    by_name = {agent["name"]: agent for agent in agents}
    assert len(by_name) == len(agents), "fixture names must be unique for these assertions"
    return by_name


def _edges(agent: dict) -> set[tuple[str, str, str, str]]:
    return {(e["target_name"], e["relationship"], e["evidence"], e["branch"]) for e in agent["topology_edges"]}


def _write(tmp_path: Path, source: str) -> Path:
    (tmp_path / "graph.py").write_text("from langgraph.graph import END, START, StateGraph\n\n" + source, encoding="utf-8")
    return tmp_path


# ── Entry and finish points ──────────────────────────────────────────────────


def test_start_edge_becomes_entry_edge_from_the_graph(tmp_path: Path):
    """``add_edge(START, "a")`` is an entry point: the graph delegates to ``a`` first."""
    root = _write(
        tmp_path,
        "g = StateGraph(dict)\ng.add_node('a', lambda s: s)\ng.add_node('b', lambda s: s)\ng.add_edge(START, 'a')\ng.add_edge('a', 'b')\n",
    )
    agents = _payloads(root)

    assert ("a", "delegated_to", "StateGraph.add_edge(START)", "") in _edges(agents["g"])
    entry = next(e for e in agents["g"]["topology_edges"] if e["target_name"] == "a")
    assert entry["provenance"] == "declared"
    assert entry["confidence"] == "high"
    assert entry["target_id"] == agents["a"]["stable_id"]


def test_set_entry_point_and_set_finish_point_are_entry_and_finish_edges(tmp_path: Path):
    root = _write(
        tmp_path,
        "g = StateGraph(dict)\ng.add_node('a', lambda s: s)\ng.add_node('b', lambda s: s)\n"
        "g.set_entry_point('a')\ng.add_edge('a', 'b')\ng.set_finish_point('b')\n",
    )
    agents = _payloads(root)

    assert ("a", "delegated_to", "StateGraph.set_entry_point", "") in _edges(agents["g"])
    assert ("g", "delegated_to", "StateGraph.set_finish_point", "") in _edges(agents["b"])


def test_end_edge_becomes_finish_edge_to_the_graph(tmp_path: Path):
    root = _write(tmp_path, "g = StateGraph(dict)\ng.add_node('a', lambda s: s)\ng.add_edge(START, 'a')\ng.add_edge('a', END)\n")
    agents = _payloads(root)

    assert ("g", "delegated_to", "StateGraph.add_edge(END)", "") in _edges(agents["a"])


def test_fan_in_edge_lists_every_source(tmp_path: Path):
    root = _write(
        tmp_path,
        "g = StateGraph(dict)\nfor n in ('a', 'b', 'c'):\n    pass\n"
        "g.add_node('a', lambda s: s)\ng.add_node('b', lambda s: s)\ng.add_node('c', lambda s: s)\ng.add_edge(['a', 'b'], 'c')\n",
    )
    agents = _payloads(root)

    assert ("c", "delegated_to", "StateGraph.add_edge", "") in _edges(agents["a"])
    assert ("c", "delegated_to", "StateGraph.add_edge", "") in _edges(agents["b"])


# ── Conditional routes ───────────────────────────────────────────────────────


def test_conditional_edges_with_dict_path_map_carry_branch_labels(tmp_path: Path):
    root = _write(
        tmp_path,
        "def route(s):\n    return s['next']\n\n"
        "g = StateGraph(dict)\ng.add_node('a', lambda s: s)\ng.add_node('b', lambda s: s)\ng.add_node('c', lambda s: s)\n"
        "g.add_conditional_edges('a', route, {'go_b': 'b', 'go_c': 'c', 'done': END})\n",
    )
    agents = _payloads(root)
    edges = _edges(agents["a"])

    assert ("b", "delegated_to", "StateGraph.add_conditional_edges", "go_b") in edges
    assert ("c", "delegated_to", "StateGraph.add_conditional_edges", "go_c") in edges
    assert ("g", "delegated_to", "StateGraph.add_conditional_edges", "done") in edges
    assert agents["a"]["dynamic_edges"] is False
    assert agents["a"]["unresolved_routes"] == []


def test_conditional_edges_with_list_path_map_use_targets_as_branches(tmp_path: Path):
    root = _write(
        tmp_path,
        "def route(s):\n    return s['next']\n\n"
        "g = StateGraph(dict)\ng.add_node('a', lambda s: s)\ng.add_node('b', lambda s: s)\ng.add_node('c', lambda s: s)\n"
        "g.add_conditional_edges('a', route, ['b', 'c'])\n",
    )
    agents = _payloads(root)
    edges = _edges(agents["a"])

    assert ("b", "delegated_to", "StateGraph.add_conditional_edges", "b") in edges
    assert ("c", "delegated_to", "StateGraph.add_conditional_edges", "c") in edges


def test_conditional_entry_point_routes_from_the_graph(tmp_path: Path):
    root = _write(
        tmp_path,
        "def route(s):\n    return s['next']\n\n"
        "g = StateGraph(dict)\ng.add_node('a', lambda s: s)\ng.add_node('b', lambda s: s)\n"
        "g.set_conditional_entry_point(route, {'x': 'a', 'y': 'b'})\n",
    )
    agents = _payloads(root)
    edges = _edges(agents["g"])

    assert ("a", "delegated_to", "StateGraph.set_conditional_entry_point", "x") in edges
    assert ("b", "delegated_to", "StateGraph.set_conditional_entry_point", "y") in edges


# ── Unresolved dynamic routes are recorded, never dropped ────────────────────


def test_conditional_edges_without_path_map_are_recorded_as_unresolved(tmp_path: Path):
    root = _write(
        tmp_path,
        "def route(s):\n    return s['next']\n\n"
        "g = StateGraph(dict)\ng.add_node('a', lambda s: s)\ng.add_node('b', lambda s: s)\n"
        "g.add_conditional_edges('a', route)\n",
    )
    agents = _payloads(root)
    a = agents["a"]

    assert a["topology_edges"] == []
    assert a["dynamic_edges"] is True
    assert a["unresolved_routes"] == [
        {
            "evidence": "StateGraph.add_conditional_edges(route)",
            "line_number": 9,
            "reason": "no path map; targets decided at runtime",
        }
    ]


def test_conditional_edges_with_non_literal_path_map_are_recorded_as_unresolved(tmp_path: Path):
    root = _write(
        tmp_path,
        "def route(s):\n    return s['next']\n\n"
        "ROUTES = {'x': 'b'}\n"
        "g = StateGraph(dict)\ng.add_node('a', lambda s: s)\ng.add_node('b', lambda s: s)\n"
        "g.add_conditional_edges('a', route, ROUTES)\n",
    )
    agents = _payloads(root)
    a = agents["a"]

    assert a["topology_edges"] == []
    assert a["dynamic_edges"] is True
    assert a["unresolved_routes"][0]["reason"] == "path map is not a literal"


def test_command_goto_with_dynamic_target_is_recorded_as_unresolved(tmp_path: Path):
    root = _write(
        tmp_path,
        "from langgraph.types import Command\n\n"
        "def a(s):\n    return Command(goto=s['next'])\n\n"
        "g = StateGraph(dict)\ng.add_node('a', a)\ng.add_node('b', lambda s: s)\n",
    )
    agents = _payloads(root)

    assert agents["a"]["dynamic_edges"] is True
    assert agents["a"]["unresolved_routes"][0]["evidence"] == "Command(goto)"


# ── Node names, subgraphs and handoffs ───────────────────────────────────────


def test_add_node_with_only_a_callable_infers_the_node_name(tmp_path: Path):
    root = _write(tmp_path, "def plan(s):\n    return s\n\ng = StateGraph(dict)\ng.add_node(plan)\ng.add_edge(START, 'plan')\n")
    agents = _payloads(root)

    assert "plan" in agents
    assert ("plan", "delegated_to", "StateGraph.add_edge(START)", "") in _edges(agents["g"])


def test_nodes_nest_under_their_graph_and_subgraphs_under_their_node(tmp_path: Path):
    root = _write(
        tmp_path,
        "child = StateGraph(dict)\nchild.add_node('inner', lambda s: s)\n"
        "parent = StateGraph(dict)\nparent.add_node('outer', lambda s: s)\nparent.add_node('sub', child.compile())\n"
        "parent.add_edge('outer', 'sub')\n",
    )
    agents = _payloads(root)

    assert agents["outer"]["parent_id"] == agents["parent"]["stable_id"]
    assert agents["sub"]["parent_id"] == agents["parent"]["stable_id"]
    assert agents["inner"]["parent_id"] == agents["child"]["stable_id"]
    assert agents["child"]["parent_id"] == agents["sub"]["stable_id"]
    assert ("child", "delegated_to", "StateGraph.add_node(subgraph)", "") in _edges(agents["sub"])
    assert agents["parent"]["parent_id"] == ""


def test_command_goto_literal_is_a_declared_handoff(tmp_path: Path):
    root = _write(
        tmp_path,
        "from langgraph.types import Command\n\n"
        "def review(s):\n    return Command(goto='writer', update={'ok': True})\n\n"
        "def escalate(s):\n    return Command(goto=['writer', 'review'])\n\n"
        "g = StateGraph(dict)\ng.add_node('review', review)\ng.add_node('writer', lambda s: s)\ng.add_node('escalate', escalate)\n",
    )
    agents = _payloads(root)

    review_edge = next(e for e in agents["review"]["topology_edges"] if e["target_name"] == "writer")
    assert review_edge["evidence"] == "Command(goto)"
    assert review_edge["provenance"] == "declared"
    assert review_edge["confidence"] == "medium"
    assert {e["target_name"] for e in agents["escalate"]["topology_edges"]} == {"writer", "review"}
    assert agents["review"]["dynamic_edges"] is False


def test_send_literal_targets_are_declared_fan_out_edges(tmp_path: Path):
    root = _write(
        tmp_path,
        "from langgraph.types import Send as LangGraphSend\n\n"
        "def supervisor(s):\n    return [LangGraphSend('writer', {'item': item}) for item in s['items']]\n\n"
        "def review(s):\n    return LangGraphSend(node='writer', arg=s)\n\n"
        "g = StateGraph(dict)\ng.add_node('supervisor', supervisor)\ng.add_node('review', review)\ng.add_node('writer', lambda s: s)\n",
    )
    agents = _payloads(root)

    for source in ("supervisor", "review"):
        edge = next(e for e in agents[source]["topology_edges"] if e["target_name"] == "writer")
        assert edge["evidence"] == "Send(node)"
        assert edge["kind"] == "fan_out"
        assert edge["provenance"] == "declared"
        assert edge["confidence"] == "medium"
        assert agents[source]["dynamic_edges"] is False

    graph = build_unified_graph_from_report({"ai_inventory": {"framework_agents": list(agents.values())}, "agents": []})
    projected = next(
        e
        for e in graph.edges
        if e.source == agents["supervisor"]["stable_id"]
        and e.target == agents["writer"]["stable_id"]
        and e.relationship == RelationshipType.DELEGATED_TO
    )
    assert projected.evidence["kind"] == "fan_out"
    assert projected.evidence["provenance"] == "declared"


def test_send_dynamic_target_is_recorded_as_unresolved(tmp_path: Path):
    root = _write(
        tmp_path,
        "from langgraph.types import Send\n\n"
        "def supervisor(s):\n    return Send(s['next'], {})\n\n"
        "g = StateGraph(dict)\ng.add_node('supervisor', supervisor)\ng.add_node('writer', lambda s: s)\n",
    )
    agents = _payloads(root)
    supervisor = agents["supervisor"]

    assert supervisor["topology_edges"] == []
    assert supervisor["dynamic_edges"] is True
    assert supervisor["unresolved_routes"] == [
        {
            "evidence": "Send(node)",
            "line_number": 6,
            "reason": "target decided at runtime",
        }
    ]


def test_send_unknown_target_is_recorded_as_unresolved(tmp_path: Path):
    root = _write(
        tmp_path,
        "from langgraph.types import Send\n\n"
        "def supervisor(s):\n    return Send('missing', {})\n\n"
        "g = StateGraph(dict)\ng.add_node('supervisor', supervisor)\n",
    )
    agents = _payloads(root)

    assert agents["supervisor"]["topology_edges"] == []
    assert agents["supervisor"]["unresolved_routes"][0]["reason"] == "target 'missing' is not a node of this graph"


# ── Fixture smoke test (#5987) and graph projection ─────────────────────────


def test_supervisor_fixture_detects_every_agent_and_route(tmp_path: Path):
    root = tmp_path / "proj"
    shutil.copytree(_FIXTURE, root)
    (root / "requirements.txt").write_text("langgraph==0.2.0\n", encoding="utf-8")

    agents = _payloads(root)
    assert {"builder", "supervisor", "research", "writer", "review", "research_builder", "search", "summarize"} <= set(agents)

    supervisor = _edges(agents["supervisor"])
    assert ("research", "delegated_to", "StateGraph.add_conditional_edges", "research") in supervisor
    assert ("writer", "delegated_to", "StateGraph.add_conditional_edges", "writer") in supervisor
    assert ("builder", "delegated_to", "StateGraph.add_conditional_edges", "__end__") in supervisor
    assert ("supervisor", "delegated_to", "StateGraph.add_edge(START)", "") in _edges(agents["builder"])
    assert ("builder", "delegated_to", "StateGraph.set_finish_point", "") in _edges(agents["writer"])
    assert ("writer", "delegated_to", "Command(goto)", "") in _edges(agents["review"])
    assert ("research_builder", "delegated_to", "StateGraph.add_node(subgraph)", "") in _edges(agents["research"])
    assert agents["review"]["unresolved_routes"][0]["evidence"] == "StateGraph.add_conditional_edges(decide)"
    assert agents["search"]["parent_id"] == agents["research_builder"]["stable_id"]

    report = scan_source(root).to_dict()
    assert report["stats"]["framework_agents"] == len(agents)


def test_unified_graph_carries_branch_and_provenance(tmp_path: Path):
    root = tmp_path / "proj"
    shutil.copytree(_FIXTURE, root)
    agents = _payloads(root)
    report = {"ai_inventory": scan_source(root).to_dict(), "agents": []}

    graph = build_unified_graph_from_report(report)
    supervisor, writer = agents["supervisor"]["stable_id"], agents["writer"]["stable_id"]
    edge = next(e for e in graph.edges if e.source == supervisor and e.target == writer and e.relationship == RelationshipType.DELEGATED_TO)

    assert edge.evidence["branch"] == "writer"
    assert edge.evidence["provenance"] == "declared"


# ── Review follow-ups: realistic API shapes that must not be silently dropped ──


def test_keyword_forms_of_add_node_and_add_conditional_edges(tmp_path: Path):
    root = _write(
        tmp_path,
        "from langgraph.types import Command\n\n"
        "def fn(s):\n    return Command(goto='b')\n\n"
        "def route(s):\n    return s['next']\n\n"
        "g = StateGraph(dict)\ng.add_node(node='a', action=fn)\ng.add_node('b', action=fn)\n"
        "g.add_conditional_edges(source='a', path=route, path_map={'x': 'b'})\n",
    )
    agents = _payloads(root)

    assert {"a", "b"} <= set(agents)
    assert ("b", "delegated_to", "StateGraph.add_conditional_edges", "x") in _edges(agents["a"])
    assert ("b", "delegated_to", "Command(goto)", "") in _edges(agents["a"])


def test_start_and_end_import_aliases_are_recognised(tmp_path: Path):
    (tmp_path / "graph.py").write_text(
        "from langgraph.graph import StateGraph\nfrom langgraph.graph import START as S, END as E\nimport langgraph.graph as lgg\n\n"
        "g = StateGraph(dict)\ng.add_node('a', lambda s: s)\ng.add_node('b', lambda s: s)\n"
        "g.add_edge(S, 'a')\ng.add_edge('a', 'b')\ng.add_edge('b', E)\ng.add_edge(lgg.START, 'b')\n",
        encoding="utf-8",
    )
    agents = _payloads(tmp_path)

    assert ("a", "delegated_to", "StateGraph.add_edge(START)", "") in _edges(agents["g"])
    assert ("b", "delegated_to", "StateGraph.add_edge(START)", "") in _edges(agents["g"])
    assert ("g", "delegated_to", "StateGraph.add_edge(END)", "") in _edges(agents["b"])


def test_unknown_edge_targets_are_recorded_as_unresolved(tmp_path: Path):
    root = _write(
        tmp_path,
        "def route(s):\n    return s['next']\n\n"
        "g = StateGraph(dict)\ng.add_node('a', lambda s: s)\n"
        "g.add_edge('a', 'typo')\ng.add_conditional_edges('a', route, {'x': 'missing'})\n",
    )
    agents = _payloads(root)
    a = agents["a"]

    assert a["topology_edges"] == []
    assert a["dynamic_edges"] is True
    reasons = {(r["evidence"], r["reason"]) for r in a["unresolved_routes"]}
    assert ("StateGraph.add_edge", "target 'typo' is not a node of this graph") in reasons
    assert ("StateGraph.add_conditional_edges", "target 'missing' is not a node of this graph") in reasons


def test_compiled_subgraph_binding_and_bare_graph_binding_nest(tmp_path: Path):
    root = _write(
        tmp_path,
        "child = StateGraph(dict)\nchild.add_node('inner', lambda s: s)\ncompiled = child.compile()\n"
        "other = StateGraph(dict)\nother.add_node('deep', lambda s: s)\n"
        "parent = StateGraph(dict)\nparent.add_node('sub', compiled)\nparent.add_node('sub2', other)\n",
    )
    agents = _payloads(root)

    assert agents["child"]["parent_id"] == agents["sub"]["stable_id"]
    assert ("child", "delegated_to", "StateGraph.add_node(subgraph)", "") in _edges(agents["sub"])
    assert agents["other"]["parent_id"] == agents["sub2"]["stable_id"]
    assert ("other", "delegated_to", "StateGraph.add_node(subgraph)", "") in _edges(agents["sub2"])


def test_fluent_chaining_resolves_the_graph_binding(tmp_path: Path):
    root = _write(
        tmp_path,
        "g = StateGraph(dict)\ng.add_node('a', lambda s: s).add_node('b', lambda s: s).add_edge('a', 'b')\n",
    )
    agents = _payloads(root)

    assert {"a", "b"} <= set(agents)
    assert ("b", "delegated_to", "StateGraph.add_edge", "") in _edges(agents["a"])


def test_add_sequence_creates_nodes_and_chained_edges(tmp_path: Path):
    root = _write(
        tmp_path,
        "def plan(s):\n    return s\n\ndef act(s):\n    return s\n\n"
        "g = StateGraph(dict)\ng.add_sequence([plan, ('do', act)])\ng.add_edge(START, 'plan')\n",
    )
    agents = _payloads(root)

    assert {"plan", "do"} <= set(agents)
    assert ("do", "delegated_to", "StateGraph.add_sequence", "") in _edges(agents["plan"])
    assert ("plan", "delegated_to", "StateGraph.add_edge(START)", "") in _edges(agents["g"])


def test_command_parent_handoff_targets_the_parent_graph(tmp_path: Path):
    root = _write(
        tmp_path,
        "from langgraph.types import Command\n\n"
        "def inner(s):\n    return Command(goto='outer', graph=Command.PARENT)\n\n"
        "child = StateGraph(dict)\nchild.add_node('inner', inner)\nchild.add_node('outer', lambda s: s)\n"
        "parent = StateGraph(dict)\nparent.add_node('outer', lambda s: s)\nparent.add_node('sub', child.compile())\n",
    )
    agents = [agent.to_dict() for agent in scan_framework_agents(root)]
    inner = next(a for a in agents if a["name"] == "inner")
    parent_outer = next(
        a for a in agents if a["name"] == "outer" and a["parent_id"] == next(p for p in agents if p["name"] == "parent")["stable_id"]
    )

    targets = {e["target_id"] for e in inner["topology_edges"]}
    assert targets == {parent_outer["stable_id"]}


def test_router_return_annotation_resolves_targets_without_a_path_map(tmp_path: Path):
    root = _write(
        tmp_path,
        "from typing import Literal\n\n"
        "def route(s) -> Literal['b', 'c', '__end__']:\n    return s['next']\n\n"
        "g = StateGraph(dict)\ng.add_node('a', lambda s: s)\ng.add_node('b', lambda s: s)\ng.add_node('c', lambda s: s)\n"
        "g.add_conditional_edges('a', route)\n",
    )
    agents = _payloads(root)
    edges = _edges(agents["a"])

    assert ("b", "delegated_to", "StateGraph.add_conditional_edges", "b") in edges
    assert ("c", "delegated_to", "StateGraph.add_conditional_edges", "c") in edges
    assert ("g", "delegated_to", "StateGraph.add_conditional_edges", "__end__") in edges
    assert agents["a"]["unresolved_routes"] == []


def test_duplicate_declarations_yield_one_edge(tmp_path: Path):
    root = _write(
        tmp_path,
        "g = StateGraph(dict)\ng.add_node('a', lambda s: s)\ng.add_node('b', lambda s: s)\ng.add_edge('a', 'b')\ng.add_edge('a', 'b')\n",
    )
    agents = _payloads(root)

    assert len(agents["a"]["topology_edges"]) == 1


def test_cytoscape_edges_carry_branch_labels(tmp_path: Path):
    root = tmp_path / "proj"
    shutil.copytree(_FIXTURE, root)
    from agent_bom.output.graph_framework_agents import append_framework_agent_elements

    class _Report:
        ai_inventory_data = scan_source(root).to_dict()

    elements: list[dict] = []
    append_framework_agent_elements(elements, _Report())  # type: ignore[arg-type]
    agents = _payloads(root)
    supervisor, writer = agents["supervisor"]["stable_id"], agents["writer"]["stable_id"]
    edge = next(el["data"] for el in elements if el["data"].get("source") == supervisor and el["data"].get("target") == writer)

    assert edge["branch"] == "writer"
