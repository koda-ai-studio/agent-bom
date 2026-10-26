"""LangGraph prebuilt multi-agent shapes: ``create_supervisor``, ``create_swarm`` and handoff tools.

These helpers build a ``StateGraph`` internally, so their wiring never appears
as ``add_edge`` calls in user code. What the library guarantees is read
straight from the call:

- ``create_supervisor([a, b])`` → supervisor → each member, and each member →
  supervisor (members hand control back), members nest under the supervisor
- ``create_swarm([a, b], default_active_agent="a")`` → swarm → each member as
  an ``entry`` edge (the router resumes whichever agent was last active); the
  default agent's edge says so in its evidence
- ``create_handoff_tool(agent_name="b")`` in agent ``a``'s ``tools`` → ``a`` → ``b``;
  a target that names no agent in the file is recorded as an unresolved route

Also here: module-level bindings that agent calls reference by name — a chat
model (``model = ChatOpenAI(model="gpt-4o")``) and a tool list (``TOOLS = [...]``).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any

from agent_bom.ai_components.framework_models import FrameworkAgent, FrameworkTopologyEdge

ORCHESTRATOR_CALLS = frozenset({"create_supervisor", "create_swarm"})
_HANDOFF_CALL = "create_handoff_tool"
_MODEL_KEYWORDS = ("model", "model_name", "model_id")


@dataclass
class PrebuiltTopology:
    edges: list[FrameworkTopologyEdge] = field(default_factory=list)
    parent_ids: dict[str, str] = field(default_factory=dict)
    unresolved_routes: dict[str, list[dict[str, Any]]] = field(default_factory=dict)


def model_bindings(tree: ast.Module) -> dict[str, str]:
    """``name = ChatX(model="m")`` / ``init_chat_model("m")`` → ``{name: "m"}`` for module-level assignments."""
    bindings: dict[str, str] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        ref = _model_literal(node.value)
        if ref:
            bindings.update({target.id: ref for target in node.targets if isinstance(target, ast.Name)})
    return bindings


def list_bindings(tree: ast.Module) -> dict[str, ast.List | ast.Tuple]:
    """Module-level ``TOOLS = [a, b]`` assignments, so ``tools=TOOLS`` reads its members."""
    bindings: dict[str, ast.List | ast.Tuple] = {}
    for node in tree.body:
        value = node.value if isinstance(node, (ast.Assign, ast.AnnAssign)) else None
        if not isinstance(value, (ast.List, ast.Tuple)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]  # type: ignore[attr-defined]
        bindings.update({target.id: value for target in targets if isinstance(target, ast.Name)})
    return bindings


def unwrap_compile(call: ast.Call) -> ast.Call:
    """``create_supervisor(...).compile(name=...)`` → the inner constructor call."""
    while isinstance(call.func, ast.Attribute) and call.func.attr == "compile" and isinstance(call.func.value, ast.Call):
        call = call.func.value
    return call


def compiled_name(call: ast.Call) -> str:
    """The ``name=`` given to ``.compile(...)`` around a constructor, if any."""
    while isinstance(call.func, ast.Attribute) and call.func.attr == "compile" and isinstance(call.func.value, ast.Call):
        name = _string(_keyword(call, "name"))
        if name:
            return name
        call = call.func.value
    return ""


def collect_prebuilt_topology(
    tree: ast.Module,
    rel_path: str,
    agents: list[FrameworkAgent],
    agent_by_binding: dict[str, FrameworkAgent],
    agent_by_line: dict[int, FrameworkAgent],
    aliases: dict[str, str],
) -> PrebuiltTopology:
    topology = PrebuiltTopology()
    handoffs = {
        target.id: target_name
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) and (target_name := _handoff_target(node.value, aliases))
        for target in node.targets
        if isinstance(target, ast.Name)
    }
    by_name = {agent.name: agent for agent in agents}
    for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
        short = _short_name(call.func, aliases)
        agent = agent_by_line.get(call.lineno)
        if agent is None:
            continue
        if short in ORCHESTRATOR_CALLS:
            _record_orchestrator(call, short, agent, agent_by_binding, rel_path, topology)
        tools = _keyword(call, "tools")
        if isinstance(tools, (ast.List, ast.Tuple)):
            for item in tools.elts:
                target = handoffs.get(item.id) if isinstance(item, ast.Name) else _handoff_target(item, aliases)
                if target:
                    _record_handoff(agent, target, by_name, call.lineno, rel_path, topology)
    return topology


def _record_orchestrator(
    call: ast.Call,
    short: str,
    orchestrator: FrameworkAgent,
    agent_by_binding: dict[str, FrameworkAgent],
    rel_path: str,
    topology: PrebuiltTopology,
) -> None:
    members_node = call.args[0] if call.args else _keyword(call, "agents")
    elements = members_node.elts if isinstance(members_node, (ast.List, ast.Tuple)) else []
    members = [agent_by_binding[item.id] for item in elements if isinstance(item, ast.Name) and item.id in agent_by_binding]
    if len(members) != len(elements) or not isinstance(members_node, (ast.List, ast.Tuple)):
        _unresolved(topology, orchestrator, f"{short}(agents)", call.lineno, "member list is not a list of agents defined in this file")
    default = _string(_keyword(call, "default_active_agent"))
    for member in members:
        if member is orchestrator:
            continue
        topology.parent_ids[member.stable_id] = orchestrator.stable_id
        if short == "create_supervisor":
            topology.edges.append(_edge(orchestrator, member, "create_supervisor(agents)", call.lineno, rel_path))
            topology.edges.append(_edge(member, orchestrator, "create_supervisor(handoff back)", call.lineno, rel_path))
        else:
            evidence = "create_swarm(default_active_agent)" if member.name == default else "create_swarm(active_agent)"
            topology.edges.append(_edge(orchestrator, member, evidence, call.lineno, rel_path, kind="entry"))


def _record_handoff(
    source: FrameworkAgent,
    target_name: str,
    by_name: dict[str, FrameworkAgent],
    line: int,
    rel_path: str,
    topology: PrebuiltTopology,
) -> None:
    target = by_name.get(target_name)
    if target is None:
        _unresolved(topology, source, _HANDOFF_CALL, line, f"handoff target {target_name!r} is not an agent in this file")
        return
    topology.edges.append(_edge(source, target, _HANDOFF_CALL, line, rel_path, confidence="medium"))


def _handoff_target(node: ast.AST, aliases: dict[str, str]) -> str:
    if not isinstance(node, ast.Call) or _short_name(node.func, aliases) != _HANDOFF_CALL:
        return ""
    return _string(_keyword(node, "agent_name"))


def _unresolved(topology: PrebuiltTopology, agent: FrameworkAgent, evidence: str, line: int, reason: str) -> None:
    topology.unresolved_routes.setdefault(agent.stable_id, []).append({"evidence": evidence, "line_number": line, "reason": reason})


def _edge(
    source: FrameworkAgent,
    target: FrameworkAgent,
    evidence: str,
    line: int,
    rel_path: str,
    *,
    kind: str = "",
    confidence: str = "high",
) -> FrameworkTopologyEdge:
    return FrameworkTopologyEdge(
        source_id=source.stable_id,
        source_name=source.name,
        target_id=target.stable_id,
        target_name=target.name,
        relationship="delegated_to",
        file_path=rel_path,
        line_number=line,
        framework="langgraph",
        evidence=evidence,
        confidence=confidence,
        provenance="declared",
        kind=kind,
    )


def _model_literal(call: ast.Call) -> str:
    for keyword in _MODEL_KEYWORDS:
        value = _string(_keyword(call, keyword))
        if value:
            return value
    if _short_name(call.func, {}) == "init_chat_model" and call.args:
        return _string(call.args[0])
    return ""


def _short_name(node: ast.AST, aliases: dict[str, str]) -> str:
    name = node.id if isinstance(node, ast.Name) else node.attr if isinstance(node, ast.Attribute) else ""
    return aliases.get(name, name)


def _keyword(call: ast.Call, name: str) -> ast.AST | None:
    return next((kw.value for kw in call.keywords if kw.arg == name), None)


def _string(node: ast.AST | None) -> str:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else ""
