"""Console view of framework-agent topology (LangGraph graphs, supervisors, swarms, crews).

One block per graph, in the order the source declares it: where control enters,
each node's routes (branch labels, handoffs, subgraphs, where it finishes), the
tools and models each node can reach, and every route the scan could not
resolve. Output is bounded; whatever is cut is counted on screen.
"""

from __future__ import annotations

from typing import Any

from rich.markup import escape

MAX_GRAPHS = 12
MAX_NODES_PER_GRAPH = 20
_MAX_TARGETS = 6
_MAX_LIST = 4
_EVIDENCE_NOTES = {"Command(goto)": "goto", "create_handoff_tool": "handoff"}


def topology_lines(framework_agents: list[dict[str, Any]]) -> list[str]:
    """Rich-markup lines describing every framework graph; empty when there is no topology."""
    agents = [agent for agent in framework_agents if isinstance(agent, dict) and agent.get("stable_id")]
    by_id = {agent["stable_id"]: agent for agent in agents}
    # A subgraph nests under the node that wraps it; that node is still a node, not a graph.
    wrapped = {
        (agent["stable_id"], edge.get("target_id"))
        for agent in agents
        for edge in agent.get("topology_edges") or []
        if isinstance(edge, dict) and edge.get("kind") == "subgraph"
    }
    children: dict[str, list[dict[str, Any]]] = {}
    for agent in agents:
        parent = agent.get("parent_id") or ""
        if parent in by_id and (parent, agent["stable_id"]) not in wrapped:
            children.setdefault(parent, []).append(agent)
    containers = [agent for agent in agents if agent["stable_id"] in children]
    if not containers:
        return []
    containers.sort(key=lambda agent: (str(agent.get("file_path") or ""), int(agent.get("line_number") or 0)))
    edge_count = sum(len(agent.get("topology_edges") or []) for agent in agents)
    unresolved = sum(len(agent.get("unresolved_routes") or []) for agent in agents)
    member_count = len({member["stable_id"] for members in children.values() for member in members})
    summary = f"{len(containers)} graph(s) · {member_count} node(s) · {edge_count} route(s)"
    if unresolved:
        summary += f" · [yellow]{unresolved} unresolved[/yellow]"
    lines = [f"  [bold]Agent graphs[/bold] [dim]({summary})[/dim]"]
    for container in containers[:MAX_GRAPHS]:
        lines.extend(_graph_lines(container, children.get(container["stable_id"], []), by_id))
    if len(containers) > MAX_GRAPHS:
        lines.append(f"  [dim]… {len(containers) - MAX_GRAPHS} more graph(s) not shown — see the JSON report or graph export[/dim]")
    return lines


def print_framework_topology(console: Any, framework_agents: list[dict[str, Any]]) -> None:
    lines = topology_lines(framework_agents)
    if lines:
        console.print("\n" + "\n".join(lines))


def _graph_lines(container: dict[str, Any], members: list[dict[str, Any]], by_id: dict[str, dict[str, Any]]) -> list[str]:
    name = _name(container)
    where = f"{container.get('file_path')}:{container.get('line_number')}"
    parent = by_id.get(container.get("parent_id") or "")
    nested = f" · subgraph of {_name(parent)}" if parent else ""
    lines = [f"\n    [bold cyan]{name}[/bold cyan] [dim]{container.get('framework')} · {escape(where)}{nested}[/dim]"]
    own = [edge for edge in container.get("topology_edges") or [] if isinstance(edge, dict)]
    for text in (
        _route_text("START", [edge for edge in own if edge.get("kind") == "entry"], container),
        _route_text(name, [edge for edge in own if edge.get("kind") != "entry"], container),
    ):
        if text:
            lines.append(f"      {text}")
    lines.extend(f"      {line}" for line in _extra_lines(container))
    members = sorted(members, key=lambda agent: int(agent.get("line_number") or 0))
    for member in members[:MAX_NODES_PER_GRAPH]:
        routes = _route_text(_name(member), member.get("topology_edges") or [], container)
        lines.append(f"      {routes or _name(member) + ' [dim](no outgoing route)[/dim]'}")
        lines.extend(f"        {line}" for line in _extra_lines(member))
    if len(members) > MAX_NODES_PER_GRAPH:
        lines.append(f"      [dim]… {len(members) - MAX_NODES_PER_GRAPH} more node(s) not shown[/dim]")
    return lines


def _route_text(source: str, edges: list[Any], container: dict[str, Any]) -> str:
    edges = [edge for edge in edges if isinstance(edge, dict) and edge.get("relationship") == "delegated_to"]
    if not edges:
        return ""
    targets = [_target_text(edge, container) for edge in edges]
    if len(targets) > _MAX_TARGETS:
        targets = [*targets[:_MAX_TARGETS], f"[dim]+{len(targets) - _MAX_TARGETS} more[/dim]"]
    return f"{source} → " + ", ".join(targets)


def _target_text(edge: dict[str, Any], container: dict[str, Any]) -> str:
    kind, branch, evidence = edge.get("kind") or "", edge.get("branch") or "", edge.get("evidence") or ""
    target = escape(str(edge.get("target_name") or "?"))
    if kind == "finish" and edge.get("target_id") == container.get("stable_id"):
        target = "END"
    elif kind == "subgraph":
        target = f"[magenta]subgraph {target}[/magenta]"
    notes = []
    if branch and branch != edge.get("target_name") and not (target == "END" and branch == "__end__"):
        notes.append(f"if {escape(branch)}")
    if evidence in _EVIDENCE_NOTES:
        notes.append(_EVIDENCE_NOTES[evidence])
    elif evidence.endswith("(default_active_agent)"):
        notes.append("default")
    return target + (f" [dim]({', '.join(notes)})[/dim]" if notes else "")


def _extra_lines(agent: dict[str, Any]) -> list[str]:
    lines = []
    capabilities = [cap for cap in agent.get("capabilities") or [] if isinstance(cap, dict)]
    tools = [str(cap.get("name")) for cap in capabilities if cap.get("source") != "graph-constructor"]
    reach = []
    if tools:
        reach.append("tools: " + _clip(tools))
    if agent.get("model_refs"):
        reach.append("model: " + _clip([str(ref) for ref in agent["model_refs"]]))
    if reach:
        lines.append(f"[dim]{escape(' · '.join(reach))}[/dim]")
    for route in (agent.get("unresolved_routes") or [])[:3]:
        lines.append(f"[yellow]? unresolved[/yellow] [dim]line {route.get('line_number')}: {escape(str(route.get('reason') or ''))}[/dim]")
    extra = len(agent.get("unresolved_routes") or []) - 3
    if extra > 0:
        lines.append(f"[yellow]? {extra} more unresolved route(s)[/yellow]")
    return lines


def _clip(values: list[str]) -> str:
    return ", ".join(values[:_MAX_LIST]) + (f" +{len(values) - _MAX_LIST}" if len(values) > _MAX_LIST else "")


def _name(agent: dict[str, Any] | None) -> str:
    return escape(str((agent or {}).get("name") or "?"))
