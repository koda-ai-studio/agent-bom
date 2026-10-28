"""Two scanned projects that share a directory name keep distinct framework agents."""

from __future__ import annotations

from pathlib import Path

from agent_bom.ai_components.framework_agents import scan_framework_agents

GRAPH = """
from langgraph.graph import StateGraph, START, END

builder = StateGraph(dict)
builder.add_node("{first}", lambda s: s)
builder.add_node("writer", lambda s: s)
builder.add_edge(START, "{first}")
builder.add_edge("{first}", "writer")
builder.add_edge("writer", END)
graph = builder.compile()
"""


def _project(parent: Path, first: str) -> Path:
    root = parent / "app"
    root.mkdir(parents=True)
    (root / "graph.py").write_text(GRAPH.format(first=first), encoding="utf-8")
    return root


def test_same_basename_projects_are_not_merged(tmp_path: Path) -> None:
    team_a = _project(tmp_path / "teamA", "research")
    team_b = _project(tmp_path / "teamB", "editor")

    alone_a = scan_framework_agents(team_a)
    alone_b = scan_framework_agents(team_b)
    together = scan_framework_agents(team_a, team_b)

    assert len(together) == len(alone_a) + len(alone_b)
    ids = [agent.stable_id for agent in together]
    assert len(ids) == len(set(ids))
    names_b = {agent.name for agent in together if agent.stable_id not in {a.stable_id for a in alone_a}}
    assert "editor" in names_b and "writer" in names_b
    # The first project keeps the bare, checkout-independent scope.
    assert {agent.stable_id for agent in alone_a} <= set(ids)
    # No edge of the second project points into the first project's graph.
    first_ids = {agent.stable_id for agent in alone_a}
    for agent in together:
        if agent.stable_id in first_ids:
            continue
        for edge in agent.topology_edges:
            assert edge.target_id not in first_ids


def test_single_project_scope_stays_the_directory_name(tmp_path: Path) -> None:
    root = _project(tmp_path / "solo", "research")
    agents = scan_framework_agents(root)
    assert agents and all(agent.scope == "app" for agent in agents)
