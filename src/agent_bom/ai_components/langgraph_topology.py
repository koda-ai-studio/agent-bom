"""LangGraph ``StateGraph`` topology: nodes, edges, routes, subgraphs and handoffs.

A ``StateGraph`` binding is itself a framework agent (the orchestrator). Its
``add_node`` calls become member agents nested under it, and the wiring calls
become ``delegated_to`` edges with ``declared`` provenance:

- ``add_edge(START, "a")`` / ``set_entry_point("a")`` → graph → ``a`` (kind ``entry``)
- ``add_edge("a", END)`` / ``set_finish_point("a")`` → ``a`` → graph (kind ``finish``:
  control returns to the graph, it is not a delegation back to it)
- ``add_conditional_edges("a", route, {label: target})`` → ``a`` → target, one
  edge per branch, carrying the branch label; without a path map the router's
  ``Literal[...]`` return annotation supplies the targets
- ``add_sequence([a, b])`` → ``a`` → ``b``
- ``add_node("sub", child.compile())`` → ``sub`` → ``child`` (kind ``subgraph``)
  and ``child`` nests under ``sub``
- ``return Command(goto="b")`` inside a node function → node → ``b`` (handoff);
  ``graph=Command.PARENT`` resolves ``b`` in the enclosing graph

Graph bindings and node functions resolve through lexical scope, so two
functions that each build a ``builder`` describe two graphs, and same-named
methods of different classes stay distinct.

Routes the parser cannot resolve statically (no path map and no annotation, a
non-literal path map or member, a computed ``goto``, a target that is not a
node of the graph) are recorded on the source node as unresolved routes and
mark it ``dynamic_edges`` so they are never silently dropped. Output is
bounded per call and per file; a cap that is hit is itself recorded as a
``truncated`` unresolved route.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any

from agent_bom.ai_components.framework_models import FrameworkAgent, FrameworkTopologyEdge
from agent_bom.ai_components.python_scopes import ScopeIndex

# Bounds for hostile or generated sources: past a cap the remaining routes are
# recorded once as a "truncated" unresolved route instead of being emitted.
MAX_EDGES_PER_FILE = 5_000
MAX_TARGETS_PER_CALL = 256
MAX_UNRESOLVED_PER_FILE = 1_000

_START = "__start__"
_END = "__end__"
_CONDITIONAL_CALLS = {
    "add_conditional_edges": "StateGraph.add_conditional_edges",
    "set_conditional_entry_point": "StateGraph.set_conditional_entry_point",
}
_WIRING_CALLS = ("add_edge", "add_sequence", "set_entry_point", "set_finish_point", *_CONDITIONAL_CALLS)
_SUBGRAPH_EVIDENCE = "StateGraph.add_node(subgraph)"


@dataclass
class LangGraphTopology:
    """Everything the LangGraph pass adds on top of the generic framework scan."""

    node_agents: list[FrameworkAgent] = field(default_factory=list)
    edges: list[FrameworkTopologyEdge] = field(default_factory=list)
    parent_ids: dict[str, str] = field(default_factory=dict)
    unresolved_routes: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    # ``add_node("tools", ToolNode(TOOLS))``: the tools expression per node id.
    node_tools: dict[str, ast.AST] = field(default_factory=dict)
    truncated: bool = False
    _unresolved_count: int = 0

    def unresolved(self, agent: FrameworkAgent, evidence: str, line_number: int, reason: str) -> None:
        if self.truncated:
            return
        if self._unresolved_count >= MAX_UNRESOLVED_PER_FILE:
            self._truncate(agent, evidence, line_number, f"per-file cap of {MAX_UNRESOLVED_PER_FILE} unresolved routes")
            return
        self._unresolved_count += 1
        self._record(agent, evidence, line_number, reason)

    def emit(self, edge: FrameworkTopologyEdge, source: FrameworkAgent, evidence: str, line_number: int) -> bool:
        """Append ``edge`` unless the per-file edge cap is reached; returns whether more edges are accepted."""
        if self.truncated:
            return False
        if len(self.edges) >= MAX_EDGES_PER_FILE:
            self._truncate(source, evidence, line_number, f"per-file cap of {MAX_EDGES_PER_FILE} edges")
            return False
        self.edges.append(edge)
        return True

    def capped(self, items: list[Any], agent: FrameworkAgent, evidence: str, line_number: int) -> list[Any]:
        """The first ``MAX_TARGETS_PER_CALL`` targets of one call; the overflow is recorded."""
        if len(items) <= MAX_TARGETS_PER_CALL:
            return items
        reason = (
            f"truncated: {len(items)} targets exceed the per-call cap of {MAX_TARGETS_PER_CALL}; the first {MAX_TARGETS_PER_CALL} were read"
        )
        self.unresolved(agent, evidence, line_number, reason)
        return items[:MAX_TARGETS_PER_CALL]

    def _truncate(self, agent: FrameworkAgent, evidence: str, line_number: int, cap: str) -> None:
        self.truncated = True
        self._record(agent, evidence, line_number, f"truncated: {cap} reached; later routes in this file were not read")

    def _record(self, agent: FrameworkAgent, evidence: str, line_number: int, reason: str) -> None:
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

    def has_ancestor(self, other: _GraphScope) -> bool:
        """Whether ``other`` is this graph or encloses it; a visited set stops on malformed chains."""
        seen: set[int] = set()
        current: _GraphScope | None = self
        while current is not None and id(current) not in seen:
            if current is other:
                return True
            seen.add(id(current))
            current = current.parent
        return False


@dataclass(frozen=True)
class _Command:
    """One ``Command(goto=...)`` in a node function, read once however many nodes share it."""

    line: int
    targets: list[str]
    to_parent: bool


class _Module:
    """Module-level facts the passes share: graph scopes, START/END aliases, functions by qualified name."""

    def __init__(
        self,
        tree: ast.Module,
        rel_path: str,
        credential_refs: list[str],
        graph_bindings: dict[tuple[str, str], FrameworkAgent],
        index: ScopeIndex,
    ) -> None:
        self.tree = tree
        self.rel_path = rel_path
        self.credential_refs = credential_refs
        self.index = index
        self.scopes = {key: _GraphScope(agent) for key, agent in graph_bindings.items() if agent.framework == "langgraph"}
        self.compiled_bindings: dict[tuple[str, str], _GraphScope] = {}
        self.constants: dict[str, str] = {"START": _START, "END": _END}
        self._commands: dict[str, list[_Command]] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name in ("START", "END") and alias.asname:
                        self.constants[alias.asname] = self.constants[alias.name]
            elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                binding = _first_target_name(node.targets)
                child = self.subgraph_scope(node.value, index.scope_of(node))
                if child is not None and binding:
                    self.compiled_bindings[(index.scope_of(node), binding)] = child

    def scope_for(self, receiver: ast.AST, scope: str) -> _GraphScope | None:
        """The graph a method is called on, through fluent chains such as ``g.add_node(...).add_edge(...)``."""
        while isinstance(receiver, ast.Call) and isinstance(receiver.func, ast.Attribute):
            receiver = receiver.func.value
        return self.index.lookup(self.scopes, scope, receiver.id) if isinstance(receiver, ast.Name) else None

    def subgraph_scope(self, action: ast.AST | None, scope: str) -> _GraphScope | None:
        """The child graph behind ``child.compile()``, a compiled binding, or a bare graph binding."""
        if isinstance(action, ast.Call) and isinstance(action.func, ast.Attribute) and action.func.attr == "compile":
            action = action.func.value
            return self.index.lookup(self.scopes, scope, action.id) if isinstance(action, ast.Name) else None
        if not isinstance(action, ast.Name):
            return None
        return self.index.lookup(self.compiled_bindings, scope, action.id) or self.index.lookup(self.scopes, scope, action.id)

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

    def router_targets(self, path: ast.AST | None, scope: str) -> list[str]:
        """Targets a ``-> Literal["a", "b"]`` router annotation declares (``Command[Literal[...]]`` is a node, not a router)."""
        definitions = self.index.functions.get(self.index.resolve_function(path, scope), [])
        annotation = definitions[-1].returns if definitions else None
        if not isinstance(annotation, ast.Subscript) or _call_name(annotation.value).split(".")[-1] != "Literal":
            return []
        elts = annotation.slice.elts if isinstance(annotation.slice, ast.Tuple) else [annotation.slice]
        refs = [self.node_ref(item) for item in elts]
        return [] if any(ref is None for ref in refs) else [ref for ref in refs if ref is not None]

    def commands(self, qualname: str) -> list[_Command]:
        """``Command(goto=...)`` calls inside the function ``qualname``, parsed once per function."""
        if qualname not in self._commands:
            found: list[_Command] = []
            for definition in self.index.functions.get(qualname, []):
                for call in ast.walk(definition):
                    if not isinstance(call, ast.Call) or _call_name(call.func).split(".")[-1] != "Command":
                        continue
                    goto = _keyword_value(call, "goto")
                    if goto is not None:
                        to_parent = _call_name(_keyword_value(call, "graph")).endswith("PARENT")
                        found.append(_Command(call.lineno, self.node_refs(goto), to_parent))
            self._commands[qualname] = found
        return self._commands[qualname]


def collect_langgraph_topology(
    tree: ast.Module,
    rel_path: str,
    credential_refs: list[str],
    graph_bindings: dict[tuple[str, str], FrameworkAgent],
    index: ScopeIndex,
) -> LangGraphTopology:
    """Collect LangGraph member nodes, wiring edges, nesting and unresolved routes.

    ``graph_bindings`` keys each framework agent by ``(enclosing scope, binding name)``.
    """
    topology = LangGraphTopology()
    module = _Module(tree, rel_path, credential_refs, graph_bindings, index)
    if not module.scopes:
        return topology
    for call in _method_calls(tree, "add_node", "add_sequence"):
        scope = module.scope_for(call.func.value, index.scope_of(call))  # type: ignore[attr-defined]
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
        scope = module.scope_for(call.func.value, index.scope_of(call))  # type: ignore[attr-defined]
        if scope is not None and call.func.attr != "add_sequence":  # type: ignore[attr-defined]
            _record_wiring(module, scope, call, topology)
        if topology.truncated:
            return topology
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
    call_scope = module.index.scope_of(call)
    child = module.subgraph_scope(action, call_scope)
    if child is not None and child is not scope:
        if scope.has_ancestor(child):
            reason = f"subgraph {child.graph.name!r} already encloses this graph; nesting would form a parent cycle and is not recorded"
            topology.unresolved(node_agent, _SUBGRAPH_EVIDENCE, call.lineno, reason)
        else:
            child.parent = scope
            topology.parent_ids[child.graph.stable_id] = node_agent.stable_id
        edge = _edge(node_agent, child.graph, _SUBGRAPH_EVIDENCE, call.lineno, module.rel_path, "high", kind="subgraph")
        topology.emit(edge, node_agent, _SUBGRAPH_EVIDENCE, call.lineno)
        return
    if isinstance(action, ast.Call) and _call_name(action.func).split(".")[-1] == "ToolNode":
        tools = _arg(action, 0, "tools")
        if tools is not None:
            topology.node_tools[node_agent.stable_id] = tools
        return
    qualname = module.index.resolve_function(action, call_scope)
    if qualname:
        scope.node_by_function.setdefault(qualname, []).append(node_agent.name)


def _record_sequence(module: _Module, scope: _GraphScope, call: ast.Call, topology: LangGraphTopology) -> None:
    """``add_sequence([fn, ("name", fn), ...])`` adds the nodes and chains them in order."""
    evidence = "StateGraph.add_sequence"
    items = call.args[0] if call.args else _keyword_value(call, "nodes")
    if not isinstance(items, (ast.List, ast.Tuple)):
        topology.unresolved(scope.graph, evidence, call.lineno, "sequence is not a literal")
        return
    previous: FrameworkAgent | None = None
    for item in topology.capped(list(items.elts), scope.graph, evidence, call.lineno):
        name, action = (_string_literal(item.elts[0]), item.elts[1]) if isinstance(item, ast.Tuple) and len(item.elts) == 2 else ("", item)
        if not name and isinstance(action, ast.Name):
            name = action.id
        current = _add_node(module, scope, name, call, topology) or scope.nodes.get(name)
        if current is None:
            topology.unresolved(scope.graph, evidence, call.lineno, "sequence member is not a static node")
            previous = None
            continue
        _record_action(module, scope, current, action, call, topology)
        if previous is not None:
            topology.emit(_edge(previous, current, evidence, call.lineno, module.rel_path, "high"), previous, evidence, call.lineno)
        previous = current


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
        source_refs = topology.capped(module.node_refs(_arg(call, 0, "start_key")), scope.graph, "StateGraph.add_edge", line)
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
    source_ref: str | None = _START
    if method == "set_conditional_entry_point":
        path, path_map = _arg(call, 0, "path"), _arg(call, 1, "path_map")
    else:
        source_ref, path, path_map = module.node_ref(_arg(call, 0, "source")), _arg(call, 1, "path"), _arg(call, 2, "path_map")
    source = scope.resolve(source_ref)
    if source is None:
        topology.unresolved(scope.graph, evidence, line, f"source {source_ref!r} is not a node of this graph")
        return
    branches = _branches(module, path_map)
    if branches is None and path_map is None:
        branches = [(ref, ref) for ref in module.router_targets(path, module.index.scope_of(call))] or None
    if branches is None:
        reason = "no path map; targets decided at runtime" if path_map is None else "path map is not a literal"
        topology.unresolved(source, f"{evidence}({_call_name(path) or 'path'})", line, reason)
        return
    for branch, target_ref in topology.capped(branches, source, evidence, line):
        _link(module, scope, source_ref, target_ref, evidence, line, topology, branch=branch, confidence="medium")


def _branches(module: _Module, path_map: ast.AST | None) -> list[tuple[str, str | None]] | None:
    """``{label: target}`` or ``[target, ...]`` as (branch, target) pairs; ``None`` when not static.

    A non-literal target keeps its slot with target ``None`` so it is recorded
    as unresolved rather than dropped.
    """
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
        return [(ref or "", ref) for ref in (module.node_ref(item) for item in path_map.elts)]
    return None


# ── Command(goto=...) handoffs ───────────────────────────────────────────────


def _record_handoffs(module: _Module, scope: _GraphScope, topology: LangGraphTopology) -> None:
    for qualname, node_names in scope.node_by_function.items():
        commands = module.commands(qualname)
        for node_name in node_names:
            for command in commands:
                _record_command(module, scope, scope.nodes[node_name], command, topology)
                if topology.truncated:
                    return


def _record_command(module: _Module, scope: _GraphScope, source: FrameworkAgent, command: _Command, topology: LangGraphTopology) -> None:
    evidence = "Command(goto)"
    target_scope = scope.parent if command.to_parent else scope
    if target_scope is None:
        topology.unresolved(source, evidence, command.line, "graph=Command.PARENT but the parent graph is not in this module")
        return
    if not command.targets:
        topology.unresolved(source, evidence, command.line, "goto target decided at runtime")
    for target_ref in topology.capped(command.targets, source, evidence, command.line):
        target = target_scope.resolve(target_ref)
        if target is None:
            topology.unresolved(source, evidence, command.line, f"target {target_ref!r} is not a node of this graph")
            continue
        edge = _edge(source, target, evidence, command.line, module.rel_path, "medium", kind=_kind(target_scope, source, target))
        if not topology.emit(edge, source, evidence, command.line):
            return


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
    edge = _edge(source, target, evidence, line, module.rel_path, confidence, branch=branch, kind=_kind(scope, source, target))
    topology.emit(edge, source, evidence, line)


def _kind(scope: _GraphScope, source: FrameworkAgent, target: FrameworkAgent) -> str:
    """``entry`` from the graph to a node, ``finish`` from a node back to its graph (START/END), else ``""``."""
    if source is scope.graph:
        return "entry"
    if target is scope.graph:
        return "finish"
    return ""


def _edge(
    source: FrameworkAgent,
    target: FrameworkAgent,
    evidence: str,
    line: int,
    rel_path: str,
    confidence: str,
    *,
    branch: str = "",
    kind: str = "",
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
        kind=kind,
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
