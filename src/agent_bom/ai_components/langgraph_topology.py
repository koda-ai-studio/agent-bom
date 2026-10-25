"""LangGraph ``StateGraph`` topology: nodes, edges, routes, subgraphs and handoffs.

A ``StateGraph`` binding is itself a framework agent (the orchestrator). Its
``add_node`` calls become member agents nested under it, and the wiring calls
become ``delegated_to`` edges with ``declared`` provenance:

- ``add_edge(START, "a")`` / ``set_entry_point("a")`` → graph → ``a`` (entry)
- ``add_edge("a", END)`` / ``set_finish_point("a")`` → ``a`` → graph (finish)
- ``add_conditional_edges("a", route, {label: target})`` → ``a`` → target, one
  edge per branch, carrying the branch label; without a path map the router's
  ``Literal[...]`` return annotation supplies the targets
- ``add_sequence([a, b])`` → ``a`` → ``b``
- ``add_node("sub", child.compile())`` → ``sub`` → ``child`` and ``child`` nests
  under ``sub``
- ``return Command(goto="b")`` inside a node function → node → ``b`` (handoff);
  ``graph=Command.PARENT`` resolves ``b`` in the enclosing graph

Routes the parser cannot resolve statically (no path map and no annotation, a
non-literal path map, a computed ``goto``, a target that is not a node of the
graph) are recorded on the source node as unresolved routes and mark it
``dynamic_edges`` so they are never silently dropped.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any

from agent_bom.ai_components.framework_models import FrameworkAgent, FrameworkTopologyEdge

_START = "__start__"
_END = "__end__"
_CONDITIONAL_CALLS = {
    "add_conditional_edges": "StateGraph.add_conditional_edges",
    "set_conditional_entry_point": "StateGraph.set_conditional_entry_point",
}
_WIRING_CALLS = ("add_edge", "add_sequence", "set_entry_point", "set_finish_point", *_CONDITIONAL_CALLS)


@dataclass
class LangGraphTopology:
    """Everything the LangGraph pass adds on top of the generic framework scan."""

    node_agents: list[FrameworkAgent] = field(default_factory=list)
    edges: list[FrameworkTopologyEdge] = field(default_factory=list)
    parent_ids: dict[str, str] = field(default_factory=dict)
    unresolved_routes: dict[str, list[dict[str, Any]]] = field(default_factory=dict)

    def unresolved(self, agent: FrameworkAgent, evidence: str, line_number: int, reason: str) -> None:
        self.unresolved_routes.setdefault(agent.stable_id, []).append({"evidence": evidence, "line_number": line_number, "reason": reason})


class _GraphScope:
    """Member nodes of one ``StateGraph`` binding and the functions behind them."""

    def __init__(self, graph: FrameworkAgent) -> None:
        self.graph = graph
        self.nodes: dict[str, FrameworkAgent] = {}
        self.node_by_function: dict[str, list[str]] = {}
        self.parent: _GraphScope | None = None

    def resolve(self, ref: str | None) -> FrameworkAgent | None:
        """The agent a node reference names; ``START``/``END`` resolve to the graph itself."""
        if ref in {_START, _END}:
            return self.graph
        return self.nodes.get(ref or "")


class _Module:
    """Module-level facts the passes share: graph scopes, START/END aliases, router annotations."""

    def __init__(self, tree: ast.Module, rel_path: str, credential_refs: list[str], agent_by_binding: dict[str, FrameworkAgent]) -> None:
        self.tree = tree
        self.rel_path = rel_path
        self.credential_refs = credential_refs
        self.scopes = {binding: _GraphScope(agent) for binding, agent in agent_by_binding.items() if agent.framework == "langgraph"}
        self.compiled_bindings: dict[str, str] = {}
        self.constants: dict[str, str] = {"START": _START, "END": _END}
        self.router_targets: dict[str, list[str]] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name in ("START", "END") and alias.asname:
                        self.constants[alias.asname] = self.constants[alias.name]
            elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                child = _subgraph_binding(node.value)
                binding = _first_target_name(node.targets)
                if child in self.scopes and binding:
                    self.compiled_bindings[binding] = child
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                targets = self.literal_targets(node.returns)
                if targets:
                    self.router_targets[node.name] = targets

    def scope_for(self, receiver: ast.AST) -> _GraphScope | None:
        """The graph a method is called on, through fluent chains such as ``g.add_node(...).add_edge(...)``."""
        while isinstance(receiver, ast.Call) and isinstance(receiver.func, ast.Attribute):
            receiver = receiver.func.value
        return self.scopes.get(_call_name(receiver))

    def subgraph_scope(self, action: ast.AST | None) -> _GraphScope | None:
        """The child graph behind ``child.compile()``, a compiled binding, or a bare graph binding."""
        binding = _subgraph_binding(action)
        if not binding and isinstance(action, ast.Name):
            binding = self.compiled_bindings.get(action.id, action.id)
        return self.scopes.get(binding) if binding else None

    def node_ref(self, node: ast.AST | None) -> str | None:
        """A node name, ``__start__``/``__end__`` for the START/END constants, or ``None`` when dynamic."""
        literal = _string_literal(node)
        if literal:
            return literal
        name = node.id if isinstance(node, ast.Name) else node.attr if isinstance(node, ast.Attribute) else ""
        return self.constants.get(name)

    def node_refs(self, node: ast.AST | None) -> list[str]:
        """One or several static node references; empty when any element is dynamic."""
        items = node.elts if isinstance(node, (ast.List, ast.Tuple, ast.Set)) else [node]
        refs = [self.node_ref(item) for item in items]
        return [] if any(ref is None for ref in refs) else [ref for ref in refs if ref is not None]

    def literal_targets(self, annotation: ast.AST | None) -> list[str]:
        """Targets a ``-> Literal["a", "b"]`` router annotation declares (``Command[Literal[...]]`` is a node, not a router)."""
        if not isinstance(annotation, ast.Subscript) or _call_name(annotation.value).split(".")[-1] != "Literal":
            return []
        elts = annotation.slice.elts if isinstance(annotation.slice, ast.Tuple) else [annotation.slice]
        refs = [self.node_ref(item) for item in elts]
        return [] if any(ref is None for ref in refs) else [ref for ref in refs if ref is not None]


def collect_langgraph_topology(
    tree: ast.Module,
    rel_path: str,
    credential_refs: list[str],
    agent_by_binding: dict[str, FrameworkAgent],
) -> LangGraphTopology:
    """Collect LangGraph member nodes, wiring edges, nesting and unresolved routes."""
    topology = LangGraphTopology()
    module = _Module(tree, rel_path, credential_refs, agent_by_binding)
    if not module.scopes:
        return topology
    for call in _method_calls(tree, "add_node", "add_sequence"):
        scope = module.scope_for(call.func.value)  # type: ignore[attr-defined]
        if scope is None:
            continue
        if call.func.attr == "add_sequence":  # type: ignore[attr-defined]
            _record_sequence(module, scope, call, topology)
            continue
        node_name, action = _node_name_and_action(call)
        node_agent = _add_node(module, scope, node_name, call, topology)
        if node_agent is not None:
            _record_action(module, scope, node_agent, action, call, topology)
    for call in _method_calls(tree, *_WIRING_CALLS):
        scope = module.scope_for(call.func.value)  # type: ignore[attr-defined]
        if scope is not None and call.func.attr != "add_sequence":  # type: ignore[attr-defined]
            _record_wiring(module, scope, call, topology)
    for scope in module.scopes.values():
        _record_handoffs(module, scope, topology)
    return topology


# ── add_node / add_sequence ──────────────────────────────────────────────────


def _add_node(module: _Module, scope: _GraphScope, node_name: str, call: ast.Call, topology: LangGraphTopology) -> FrameworkAgent | None:
    if not node_name or node_name in scope.nodes:
        return None
    node_agent = FrameworkAgent(
        framework="langgraph",
        name=node_name,
        file_path=module.rel_path,
        line_number=getattr(call, "lineno", 1),
        credential_refs=module.credential_refs,
        confidence="medium",
    )
    scope.nodes[node_name] = node_agent
    topology.node_agents.append(node_agent)
    topology.parent_ids[node_agent.stable_id] = scope.graph.stable_id
    return node_agent


def _node_name_and_action(call: ast.Call) -> tuple[str, ast.AST | None]:
    """``add_node("name", fn)``, ``add_node(fn)`` (name inferred from ``fn``) or the keyword form ``add_node(node=, action=)``."""
    first = call.args[0] if call.args else _keyword_value(call, "node")
    action = call.args[1] if len(call.args) > 1 else _keyword_value(call, "action")
    literal = _string_literal(first)
    if literal:
        return literal, action
    if isinstance(first, ast.Name):
        return first.id, first
    if isinstance(first, ast.Attribute):
        return first.attr, first
    return "", None


def _record_action(
    module: _Module,
    scope: _GraphScope,
    node_agent: FrameworkAgent,
    action: ast.AST | None,
    call: ast.Call,
    topology: LangGraphTopology,
) -> None:
    """Nest a subgraph under the node, or remember the function behind it for handoffs."""
    child = module.subgraph_scope(action)
    if child is not None and child is not scope:
        child.parent = scope
        topology.parent_ids[child.graph.stable_id] = node_agent.stable_id
        topology.edges.append(_edge(node_agent, child.graph, "StateGraph.add_node(subgraph)", call.lineno, module.rel_path, "high"))
        return
    function_name = action.id if isinstance(action, ast.Name) else action.attr if isinstance(action, ast.Attribute) else ""
    if function_name:
        scope.node_by_function.setdefault(function_name, []).append(node_agent.name)


def _record_sequence(module: _Module, scope: _GraphScope, call: ast.Call, topology: LangGraphTopology) -> None:
    """``add_sequence([fn, ("name", fn), ...])`` adds the nodes and chains them in order."""
    items = call.args[0] if call.args else _keyword_value(call, "nodes")
    if not isinstance(items, (ast.List, ast.Tuple)):
        topology.unresolved(scope.graph, "StateGraph.add_sequence", call.lineno, "sequence is not a literal")
        return
    previous: FrameworkAgent | None = None
    for item in items.elts:
        name, action = (_string_literal(item.elts[0]), item.elts[1]) if isinstance(item, ast.Tuple) and len(item.elts) == 2 else ("", item)
        if not name and isinstance(action, ast.Name):
            name = action.id
        current = _add_node(module, scope, name, call, topology) or scope.nodes.get(name)
        if current is None:
            topology.unresolved(scope.graph, "StateGraph.add_sequence", call.lineno, "sequence member is not a static node")
            previous = None
            continue
        _record_action(module, scope, current, action, call, topology)
        if previous is not None:
            topology.edges.append(_edge(previous, current, "StateGraph.add_sequence", call.lineno, module.rel_path, "high"))
        previous = current


def _subgraph_binding(action: ast.AST | None) -> str:
    """The graph binding behind an inline ``child.compile()`` call."""
    if isinstance(action, ast.Call) and isinstance(action.func, ast.Attribute) and action.func.attr == "compile":
        return _call_name(action.func.value)
    return ""


# ── add_edge / entry / finish / conditional ─────────────────────────────────


def _record_wiring(module: _Module, scope: _GraphScope, call: ast.Call, topology: LangGraphTopology) -> None:
    method = call.func.attr  # type: ignore[attr-defined]
    line = getattr(call, "lineno", 1)
    if method in _CONDITIONAL_CALLS:
        _record_conditional(module, scope, call, topology)
        return
    if method == "set_entry_point":
        _link(module, scope, _START, module.node_ref(_arg(call, 0, "key")), "StateGraph.set_entry_point", line, topology)
    elif method == "set_finish_point":
        _link(module, scope, module.node_ref(_arg(call, 0, "key")), _END, "StateGraph.set_finish_point", line, topology)
    elif method == "add_edge":
        target_ref = module.node_ref(_arg(call, 1, "end_key"))
        start = _arg(call, 0, "start_key")
        source_refs = module.node_refs(start)
        if not source_refs:
            topology.unresolved(scope.graph, "StateGraph.add_edge", line, "edge source is not a static node reference")
        for source_ref in source_refs:
            evidence = "StateGraph.add_edge"
            if source_ref == _START:
                evidence = "StateGraph.add_edge(START)"
            elif target_ref == _END:
                evidence = "StateGraph.add_edge(END)"
            _link(module, scope, source_ref, target_ref, evidence, line, topology)


def _record_conditional(module: _Module, scope: _GraphScope, call: ast.Call, topology: LangGraphTopology) -> None:
    method = call.func.attr  # type: ignore[attr-defined]
    evidence = _CONDITIONAL_CALLS[method]
    line = getattr(call, "lineno", 1)
    if method == "set_conditional_entry_point":
        source_ref, path, path_map = _START, _arg(call, 0, "path"), _arg(call, 1, "path_map")
    else:
        source_ref, path, path_map = module.node_ref(_arg(call, 0, "source")), _arg(call, 1, "path"), _arg(call, 2, "path_map")
    source = scope.resolve(source_ref)
    if source is None:
        topology.unresolved(scope.graph, evidence, line, f"source {source_ref!r} is not a node of this graph")
        return
    branches = _branches(module, path_map)
    if branches is None and path_map is None:
        branches = [(ref, ref) for ref in module.router_targets.get(_call_name(path), [])] or None
    if branches is None:
        reason = "no path map; targets decided at runtime" if path_map is None else "path map is not a literal"
        topology.unresolved(source, f"{evidence}({_call_name(path) or 'path'})", line, reason)
        return
    for branch, target_ref in branches:
        _link(module, scope, source_ref, target_ref, evidence, line, topology, branch=branch, confidence="medium")


def _branches(module: _Module, path_map: ast.AST | None) -> list[tuple[str, str | None]] | None:
    """``{label: target}`` or ``[target, ...]`` as (branch, target) pairs; ``None`` when not static."""
    if isinstance(path_map, ast.Dict):
        pairs: list[tuple[str, str | None]] = []
        for key, value in zip(path_map.keys, path_map.values, strict=True):
            label = module.node_ref(key) if key is not None else None
            if label is None and isinstance(key, ast.Constant):
                label = str(key.value)
            if label is None:
                return None
            pairs.append((label, module.node_ref(value)))
        return pairs
    if isinstance(path_map, (ast.List, ast.Tuple)):
        return [(ref, ref) for ref in (module.node_ref(item) for item in path_map.elts) if ref is not None]
    return None


# ── Command(goto=...) handoffs ───────────────────────────────────────────────


def _record_handoffs(module: _Module, scope: _GraphScope, topology: LangGraphTopology) -> None:
    for func in ast.walk(module.tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node_name in scope.node_by_function.get(func.name, []):
            _record_function_handoffs(module, scope, scope.nodes[node_name], func, topology)


def _record_function_handoffs(
    module: _Module,
    scope: _GraphScope,
    source: FrameworkAgent,
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    topology: LangGraphTopology,
) -> None:
    for command in ast.walk(func):
        if not isinstance(command, ast.Call) or _call_name(command.func).split(".")[-1] != "Command":
            continue
        goto = _keyword_value(command, "goto")
        if goto is None:
            continue
        target_scope = scope.parent if _call_name(_keyword_value(command, "graph")).endswith("PARENT") else scope
        if target_scope is None:
            topology.unresolved(source, "Command(goto)", command.lineno, "graph=Command.PARENT but the parent graph is not in this module")
            continue
        targets = module.node_refs(goto)
        if not targets:
            topology.unresolved(source, "Command(goto)", command.lineno, "goto target decided at runtime")
        for target_ref in targets:
            target = target_scope.resolve(target_ref)
            if target is None:
                topology.unresolved(source, "Command(goto)", command.lineno, f"target {target_ref!r} is not a node of this graph")
                continue
            topology.edges.append(_edge(source, target, "Command(goto)", command.lineno, module.rel_path, "medium"))


# ── Shared helpers ───────────────────────────────────────────────────────────


def _link(
    module: _Module,
    scope: _GraphScope,
    source_ref: str | None,
    target_ref: str | None,
    evidence: str,
    line: int,
    topology: LangGraphTopology,
    *,
    branch: str = "",
    confidence: str = "high",
) -> None:
    source, target = scope.resolve(source_ref), scope.resolve(target_ref)
    if source is None:
        topology.unresolved(scope.graph, evidence, line, f"source {source_ref!r} is not a node of this graph")
        return
    if target is None:
        reason = f"target {target_ref!r} is not a node of this graph" if target_ref else "target decided at runtime"
        topology.unresolved(source, evidence, line, reason)
        return
    if source is target and source is scope.graph:
        return
    topology.edges.append(_edge(source, target, evidence, line, module.rel_path, confidence, branch=branch))


def _edge(
    source: FrameworkAgent,
    target: FrameworkAgent,
    evidence: str,
    line: int,
    rel_path: str,
    confidence: str,
    *,
    branch: str = "",
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
        branch=branch,
        provenance="declared",
    )


def _method_calls(tree: ast.Module, *methods: str) -> list[ast.Call]:
    """``x.method(...)`` calls in source order."""
    return [
        node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in methods
    ]


def _arg(call: ast.Call, index: int, keyword: str) -> ast.AST | None:
    """Positional argument ``index``, or the keyword LangGraph names it."""
    if len(call.args) > index:
        return call.args[index]
    return _keyword_value(call, keyword)


def _keyword_value(node: ast.Call, name: str) -> ast.AST | None:
    for kw in node.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _first_target_name(targets: list[ast.expr]) -> str:
    for target in targets:
        if isinstance(target, ast.Name):
            return target.id
    return ""


def _string_literal(node: ast.AST | None) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


def _call_name(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""
