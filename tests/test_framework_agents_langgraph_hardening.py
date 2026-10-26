"""LangGraph topology hardening: hostile-input bounds, scoping, and graph projection of nesting and routes."""

from __future__ import annotations

import time
from pathlib import Path

from agent_bom.ai_components.framework_agents import scan_framework_agents
from agent_bom.ai_components.langgraph_topology import MAX_EDGES_PER_FILE, MAX_TARGETS_PER_CALL
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.types import RelationshipType

_HEADER = "from langgraph.graph import END, START, StateGraph\nfrom langgraph.types import Command\n\n"


def _write(tmp_path: Path, source: str, *, header: str = _HEADER) -> Path:
    (tmp_path / "graph.py").write_text(header + source, encoding="utf-8")
    return tmp_path


def _scan(root: Path) -> list[dict]:
    return [agent.to_dict() for agent in scan_framework_agents(root)]


def _by_name(agents: list[dict]) -> dict[str, dict]:
    by_name = {agent["name"]: agent for agent in agents}
    assert len(by_name) == len(agents), "names must be unique for these assertions"
    return by_name


def _targets(agent: dict) -> set[str]:
    return {edge["target_name"] for edge in agent["topology_edges"]}


def _all_unresolved(agents: list[dict]) -> list[dict]:
    return [route for agent in agents for route in agent["unresolved_routes"]]


# ── Hostile input: bounded time and bounded output ───────────────────────────


def test_many_graphs_in_one_file_scan_in_linear_time(tmp_path: Path):
    parts = ["def node(s):\n    return Command(goto='a')\n\n"]
    parts += [f"g{i} = StateGraph(dict)\ng{i}.add_node('a', node)\ng{i}.add_edge(START, 'a')\n" for i in range(3000)]
    root = _write(tmp_path, "".join(parts))

    started = time.perf_counter()
    agents = _scan(root)
    elapsed = time.perf_counter() - started

    assert elapsed < 5, f"3,000 graphs took {elapsed:.1f}s"
    edges = sum(len(agent["topology_edges"]) for agent in agents)
    assert edges <= MAX_EDGES_PER_FILE
    assert any(route["reason"].startswith("truncated") for route in _all_unresolved(agents))


def test_huge_goto_list_over_a_shared_function_is_capped(tmp_path: Path):
    names = ", ".join(f"'n{i}'" for i in range(4000))
    source = f"def shared(s):\n    return Command(goto=[{names}])\n\ng = StateGraph(dict)\n"
    source += "".join(f"g.add_node('n{i}', shared)\n" for i in range(4000))
    root = _write(tmp_path, source)

    started = time.perf_counter()
    agents = _scan(root)
    elapsed = time.perf_counter() - started

    assert elapsed < 5, f"4,000 x 4,000 goto took {elapsed:.1f}s"
    edges = sum(len(agent["topology_edges"]) for agent in agents)
    assert edges <= MAX_EDGES_PER_FILE
    n0 = next(agent for agent in agents if agent["name"] == "n0")
    assert len(n0["topology_edges"]) == MAX_TARGETS_PER_CALL
    assert any(route["reason"].startswith("truncated") and "per-call" in route["reason"] for route in n0["unresolved_routes"])
    unresolved = _all_unresolved(agents)
    assert any(route["reason"].startswith("truncated") and "per-file" in route["reason"] for route in unresolved)
    assert len(unresolved) <= 2 * MAX_EDGES_PER_FILE


def test_huge_conditional_path_map_is_capped_per_call(tmp_path: Path):
    count = MAX_TARGETS_PER_CALL + 50
    nodes = "".join(f"g.add_node('t{i}', lambda s: s)\n" for i in range(count))
    targets = ", ".join(f"'t{i}'" for i in range(count))
    root = _write(
        tmp_path,
        "def route(s):\n    return s\n\ng = StateGraph(dict)\ng.add_node('a', lambda s: s)\n"
        f"{nodes}g.add_conditional_edges('a', route, [{targets}])\n",
    )
    a = _by_name(_scan(root))["a"]

    assert len(a["topology_edges"]) == MAX_TARGETS_PER_CALL
    assert a["dynamic_edges"] is True
    assert any(route["reason"].startswith("truncated") for route in a["unresolved_routes"])


# ── Handoffs bind to the qualified function, not a bare name ─────────────────


def test_same_named_methods_in_different_classes_do_not_share_handoffs(tmp_path: Path):
    root = _write(
        tmp_path,
        "class Alpha:\n"
        "    def route(self, s):\n        return Command(goto='b')\n\n"
        "    def build(self):\n"
        "        g = StateGraph(dict)\n"
        "        g.add_node('a', self.route)\n        g.add_node('b', lambda s: s)\n        g.add_node('c', lambda s: s)\n"
        "        return g\n\n"
        "class Beta:\n"
        "    def route(self, s):\n        return Command(goto='c')\n",
    )
    a = _by_name(_scan(root))["a"]

    assert _targets(a) == {"b"}


def test_nested_function_shadows_module_function_of_the_same_name(tmp_path: Path):
    root = _write(
        tmp_path,
        "def worker(s):\n    return Command(goto='c')\n\n"
        "def build():\n"
        "    def worker(s):\n        return Command(goto='b')\n"
        "    g = StateGraph(dict)\n"
        "    g.add_node('a', worker)\n    g.add_node('b', lambda s: s)\n    g.add_node('c', lambda s: s)\n"
        "    return g\n",
    )
    a = _by_name(_scan(root))["a"]

    assert _targets(a) == {"b"}


# ── Same binding name in two functions stays two graphs ──────────────────────


def test_same_binding_name_in_two_functions_is_two_graphs(tmp_path: Path):
    root = _write(
        tmp_path,
        "def build_a():\n    builder = StateGraph(dict)\n    builder.add_node('x', lambda s: s)\n"
        "    builder.add_edge(START, 'x')\n    return builder\n\n"
        "def build_b():\n    builder = StateGraph(dict)\n    builder.add_node('y', lambda s: s)\n"
        "    builder.add_edge(START, 'y')\n    return builder\n",
    )
    agents = _scan(root)
    graphs = sorted((a for a in agents if a["name"] == "builder"), key=lambda a: a["line_number"])
    nodes = _by_name([a for a in agents if a["name"] != "builder"])

    assert len(graphs) == 2
    assert nodes["x"]["parent_id"] == graphs[0]["stable_id"]
    assert nodes["y"]["parent_id"] == graphs[1]["stable_id"]
    assert _targets(graphs[0]) == {"x"}
    assert _targets(graphs[1]) == {"y"}


# ── Dynamic members of a list path map are recorded, not dropped ─────────────


def test_list_path_map_records_dynamic_members_as_unresolved(tmp_path: Path):
    root = _write(
        tmp_path,
        "DYNAMIC = 'c'\n\ndef route(s):\n    return s\n\n"
        "g = StateGraph(dict)\ng.add_node('a', lambda s: s)\ng.add_node('b', lambda s: s)\n"
        "g.add_conditional_edges('a', route, ['b', DYNAMIC])\n",
    )
    a = _by_name(_scan(root))["a"]

    assert _targets(a) == {"b"}
    assert a["dynamic_edges"] is True
    assert [route["evidence"] for route in a["unresolved_routes"]] == ["StateGraph.add_conditional_edges"]


# ── Parent cycles are refused ────────────────────────────────────────────────


def test_mutual_subgraph_nesting_does_not_form_a_parent_cycle(tmp_path: Path):
    root = _write(
        tmp_path,
        "a = StateGraph(dict)\nb = StateGraph(dict)\na.add_node('x', b.compile())\nb.add_node('y', a.compile())\n",
    )
    agents = _scan(root)
    by_id = {agent["stable_id"]: agent for agent in agents}

    for agent in agents:
        seen: set[str] = set()
        current = agent
        while current["parent_id"]:
            assert current["stable_id"] not in seen, f"parent cycle through {current['name']}"
            seen.add(current["stable_id"])
            current = by_id[current["parent_id"]]
    assert any("cycle" in route["reason"] for route in _all_unresolved(agents))


# ── Entry and finish edges are labelled ──────────────────────────────────────


def test_entry_and_finish_edges_carry_their_kind(tmp_path: Path):
    root = _write(
        tmp_path,
        "g = StateGraph(dict)\ng.add_node('a', lambda s: s)\ng.add_node('b', lambda s: s)\n"
        "g.add_edge(START, 'a')\ng.add_edge('a', 'b')\ng.add_edge('b', END)\ng.set_finish_point('a')\n",
    )
    agents = _by_name(_scan(root))

    entry = next(e for e in agents["g"]["topology_edges"] if e["target_name"] == "a")
    assert entry["kind"] == "entry"
    assert {e["kind"] for e in agents["b"]["topology_edges"]} == {"finish"}
    finish_kinds = {e["evidence"]: e["kind"] for e in agents["a"]["topology_edges"]}
    assert finish_kinds == {"StateGraph.add_edge": "", "StateGraph.set_finish_point": "finish"}

    graph = build_unified_graph_from_report({"ai_inventory": {"framework_agents": list(agents.values())}, "agents": []})
    finish = next(e for e in graph.edges if e.source == agents["b"]["stable_id"] and e.target == agents["g"]["stable_id"])
    assert finish.relationship == RelationshipType.DELEGATED_TO
    assert finish.evidence["kind"] == "finish"


# ── Unified graph projection: branch labels, nesting, unresolved routes ──────


def test_unified_graph_keeps_every_branch_label_on_a_merged_edge(tmp_path: Path):
    root = _write(
        tmp_path,
        "def route(s):\n    return s\n\ng = StateGraph(dict)\ng.add_node('a', lambda s: s)\ng.add_node('b', lambda s: s)\n"
        "g.add_conditional_edges('a', route, {'retry': 'b', 'escalate': 'b'})\n",
    )
    agents = _by_name(_scan(root))
    assert len(agents["a"]["topology_edges"]) == 2

    graph = build_unified_graph_from_report({"ai_inventory": {"framework_agents": list(agents.values())}, "agents": []})
    edges = [e for e in graph.edges if e.source == agents["a"]["stable_id"] and e.target == agents["b"]["stable_id"]]

    assert len(edges) == 1
    assert edges[0].evidence["branches"] == ["escalate", "retry"]


def test_unified_graph_nodes_carry_parent_and_unresolved_routes(tmp_path: Path):
    root = _write(
        tmp_path,
        "def route(s):\n    return s\n\n"
        "child = StateGraph(dict)\nchild.add_node('inner', lambda s: s)\n"
        "g = StateGraph(dict)\ng.add_node('a', lambda s: s)\ng.add_node('sub', child.compile())\ng.add_edge(START, 'a')\n"
        "g.add_edge('a', 'sub')\ng.add_conditional_edges('a', route)\ng.add_edge('a', 'typo')\n",
    )
    agents = _by_name(_scan(root))

    graph = build_unified_graph_from_report({"ai_inventory": {"framework_agents": list(agents.values())}, "agents": []})
    a = graph.nodes[agents["a"]["stable_id"]].attributes
    child = graph.nodes[agents["child"]["stable_id"]].attributes

    assert a["parent_id"] == agents["g"]["stable_id"]
    assert child["parent_id"] == agents["sub"]["stable_id"]
    assert a["unresolved_route_count"] == 2
    assert a["unresolved_route_reasons"] == ["no path map; targets decided at runtime", "target 'typo' is not a node of this graph"]
    assert graph.nodes[agents["g"]["stable_id"]].attributes["unresolved_route_count"] == 0


# ── Aliased StateGraph import ────────────────────────────────────────────────


def test_aliased_state_graph_import_is_detected(tmp_path: Path):
    root = _write(
        tmp_path,
        "g = SG(dict)\ng.add_node('a', lambda s: s)\ng.add_edge(START, 'a')\n",
        header="from langgraph.graph import START, StateGraph as SG\n\n",
    )
    agents = _by_name(_scan(root))

    assert agents["g"]["framework"] == "langgraph"
    assert _targets(agents["g"]) == {"a"}


def test_cytoscape_edge_keeps_every_branch_label_and_kind(tmp_path: Path):
    from agent_bom.output.graph_framework_agents import append_framework_agent_elements

    root = _write(
        tmp_path,
        "def route(s):\n    return s\n\ng = StateGraph(dict)\ng.add_node('a', lambda s: s)\ng.add_node('b', lambda s: s)\n"
        "g.add_edge(START, 'a')\ng.add_conditional_edges('a', route, {'retry': 'b', 'escalate': 'b'})\n",
    )
    agents = _by_name(_scan(root))

    class _Report:
        ai_inventory_data = {"framework_agents": list(agents.values())}

    elements: list[dict] = []
    append_framework_agent_elements(elements, _Report())  # type: ignore[arg-type]
    data = [el["data"] for el in elements if "source" in el["data"]]
    route = [d for d in data if d["source"] == agents["a"]["stable_id"] and d["target"] == agents["b"]["stable_id"]]
    entry = next(d for d in data if d["source"] == agents["g"]["stable_id"] and d["target"] == agents["a"]["stable_id"])

    assert len(route) == 1
    assert route[0]["branches"] == ["escalate", "retry"]
    assert route[0]["type"] == "delegated_to"
    assert entry["kind"] == "entry"


def test_folded_construct_keeps_parent_and_unresolved_routes(tmp_path: Path):
    from agent_bom.graph.container import UnifiedGraph
    from agent_bom.graph.framework_topology_projection import _add_framework_topology
    from agent_bom.graph.node import UnifiedNode
    from agent_bom.graph.types import EntityType

    root = _write(
        tmp_path, "def route(s):\n    return s\n\ng = StateGraph(dict)\ng.add_node('a', lambda s: s)\ng.add_conditional_edges('a', route)\n"
    )
    agents = _by_name(_scan(root))
    graph = UnifiedGraph()
    graph.add_node(UnifiedNode(id="host", entity_type=EntityType.AGENT, label="project"))

    _add_framework_topology(graph, list(agents.values()), "test", host_agent_id="host")
    folded = {entry["name"]: entry for entry in graph.nodes["host"].attributes["code_agents"]}

    assert folded["a"]["parent_id"] == agents["g"]["stable_id"]
    assert folded["a"]["unresolved_route_count"] == 1
    assert folded["a"]["unresolved_route_reasons"] == ["no path map; targets decided at runtime"]
