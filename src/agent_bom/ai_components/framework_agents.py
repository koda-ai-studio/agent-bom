"""First-class non-MCP agent framework discovery.

Framework-native agents are distinct from MCP servers. Graph/fleet callers can attach
capabilities, model references, credentials, and provenance without pretending
LangGraph, AutoGen, CrewAI, or Assistants code is an MCP server.
"""

from __future__ import annotations

import ast
import os
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from agent_bom.ai_components.framework_models import FrameworkAgent, FrameworkCapability, FrameworkTopologyEdge
from agent_bom.ai_components.langgraph_prebuilt import (
    ORCHESTRATOR_CALLS,
    PREBUILT_MARKERS,
    PrebuiltTopology,
    collect_prebuilt_topology,
    compiled_name,
    list_bindings,
    model_bindings,
    unwrap_compile,
)
from agent_bom.ai_components.langgraph_topology import collect_langgraph_topology
from agent_bom.ai_components.local_shadow import declared_python_packages, is_sdk_import
from agent_bom.ai_components.project_scope import project_scope
from agent_bom.ai_components.python_scopes import ScopeIndex
from agent_bom.ast.source_reader import parse_python_source
from agent_bom.ast_signal_utils import is_agent_tool_decorator
from agent_bom.constants import is_credential_key

__all__ = ["FrameworkAgent", "FrameworkCapability", "FrameworkTopologyEdge", "scan_framework_agents"]

_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    ".env",
    "env",
    ".tox",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    "dist",
    "build",
    ".claude",
    ".codex",
}
_MAX_FILE_SIZE = 512 * 1024

_FRAMEWORK_IMPORTS: dict[str, tuple[str, ...]] = {
    "langchain": ("langchain", "langchain_core", "langchain_community"),
    "langgraph": ("langgraph", "langgraph_supervisor", "langgraph_swarm"),
    "autogen": ("autogen", "autogen_agentchat"),
    "crewai": ("crewai",),
    "openai-agents": ("agents",),
    "openai-assistants": ("openai",),
    "claude-agents": ("claude_agent_sdk", "anthropic"),
}
_FRAMEWORK_PRIORITY = (
    "langgraph",
    "langchain",
    "autogen",
    "crewai",
    "openai-agents",
    "openai-assistants",
    "claude-agents",
)
_FRAMEWORK_PACKAGES: dict[str, tuple[str, ...]] = {
    "langchain": ("langchain", "langchain-core", "langchain-community"),
    "langgraph": ("langgraph", "langgraph-supervisor", "langgraph-swarm"),
    "autogen": ("pyautogen", "autogen-agentchat"),
    "crewai": ("crewai",),
    "openai-agents": ("openai-agents",),
    "openai-assistants": ("openai",),
    "claude-agents": ("claude-agent-sdk", "anthropic"),
}
_AGENT_CALLS = {
    "Agent",
    "AssistantAgent",
    "UserProxyAgent",
    "ConversableAgent",
    "AgentExecutor",
    "Crew",
    "GroupChat",
    "StateGraph",
    "create_react_agent",
    "create_openai_functions_agent",
    "create_agent",
    *ORCHESTRATOR_CALLS,
}
_AGENT_TOOLS_ARG = {"create_react_agent", "create_agent"}
_TOOL_CALLS = {"Tool", "StructuredTool", "FunctionTool", "tool", "from_function"}
_TOOL_REGISTRATION_CALLS = {"register_function", "register_for_llm", "register_for_execution", "add_node", "add_tool"}


@dataclass(frozen=True)
class _SourceFacts:
    """Per-file lookups agent calls resolve names through."""

    tools: dict[str, FrameworkCapability]
    models: dict[str, str]
    lists: dict[str, ast.List | ast.Tuple]
    aliases: dict[str, str]


def scan_framework_agents(*paths: str | Path) -> list[FrameworkAgent]:
    """Scan Python source for framework-native agents and relationships."""
    agents: list[FrameworkAgent] = []
    seen: set[str] = set()
    scopes: dict[str, Path] = {}
    for path in paths:
        root = Path(path)
        files = [root] if root.is_file() else _iter_python_files(root)
        project_root = root if root.is_dir() else root.parent
        scope = project_scope(project_root.resolve(), scopes)
        declared = declared_python_packages(project_root)
        for filepath in files:
            for agent in _scoped(_scan_python_file(filepath, project_root, declared), scope):
                key = agent.stable_id
                if key in seen:
                    continue
                seen.add(key)
                agents.append(agent)
    return agents


def _scoped(agents: list[FrameworkAgent], scope: str) -> list[FrameworkAgent]:
    """Re-key one file's agents under the project scope, keeping their edges and nesting consistent."""
    if not scope:
        return agents
    new_ids = {agent.stable_id: replace(agent, scope=scope).stable_id for agent in agents}
    return [
        replace(
            agent,
            scope=scope,
            parent_id=new_ids.get(agent.parent_id, agent.parent_id),
            topology_edges=[
                replace(edge, source_id=new_ids.get(edge.source_id, edge.source_id), target_id=new_ids.get(edge.target_id, edge.target_id))
                for edge in agent.topology_edges
            ],
            unresolved_routes=agent.unresolved_routes,
        )
        for agent in agents
    ]


def _iter_python_files(root: Path) -> list[Path]:
    if not root.exists() or not root.is_dir():
        return []
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in _SKIP_DIRS and not name.endswith(".egg-info")]
        for filename in filenames:
            if filename.endswith(".py"):
                files.append(Path(dirpath) / filename)
    return files[:500]


def _scan_python_file(filepath: Path, root: Path, declared: frozenset[str] = frozenset()) -> list[FrameworkAgent]:
    try:
        if filepath.stat().st_size > _MAX_FILE_SIZE:
            return []
        content = filepath.read_text(encoding="utf-8", errors="replace")
        tree = parse_python_source(content, filename=str(filepath))
    except (OSError, SyntaxError):
        return []

    imports = _detect_frameworks(tree, filepath, root, declared)
    if not imports:
        return []

    rel_path = str(filepath.relative_to(root)) if filepath.is_relative_to(root) else str(filepath)
    credential_refs = _extract_credential_refs(tree)
    facts = _SourceFacts(_collect_tools(tree), model_bindings(tree), list_bindings(tree), _call_aliases(tree))
    scopes = ScopeIndex(tree)
    framework_agents: list[FrameworkAgent] = []
    agent_by_binding: dict[str, FrameworkAgent] = {}
    scoped_bindings: dict[tuple[str, str], FrameworkAgent] = {}
    agent_by_line: dict[int, FrameworkAgent] = {}

    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        binding = _first_target_name(node.targets)
        if not binding:
            continue
        call = unwrap_compile(node.value)
        fallback = compiled_name(node.value) or _string_keyword(call, "supervisor_name") or binding
        agent = _agent_from_call(call, imports, rel_path, credential_refs, facts, fallback_name=fallback)
        if not agent:
            continue
        framework_agents.append(agent)
        agent_by_binding[binding] = agent
        scoped_bindings[(scopes.scope_of(node), binding)] = agent
        agent_by_line[getattr(call, "lineno", 1)] = agent

    langgraph = collect_langgraph_topology(tree, rel_path, credential_refs, scoped_bindings, scopes)
    framework_agents.extend(langgraph.node_agents)

    agent_by_call_line = dict(agent_by_line)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if getattr(node, "lineno", 1) in agent_by_line:
            continue
        agent = _agent_from_call(node, imports, rel_path, credential_refs, facts)
        if agent:
            framework_agents.append(agent)
            agent_by_call_line.setdefault(getattr(node, "lineno", 1), agent)

    prebuilt = PrebuiltTopology()
    if any(marker in content for marker in PREBUILT_MARKERS):
        prebuilt = collect_prebuilt_topology(tree, rel_path, framework_agents, agent_by_binding, agent_by_call_line, facts.aliases)
    topology_edges = _collect_topology_edges(tree, rel_path, agent_by_binding, agent_by_line) + langgraph.edges + prebuilt.edges
    unresolved = {
        key: [*langgraph.unresolved_routes.get(key, []), *prebuilt.unresolved_routes.get(key, [])]
        for key in {*langgraph.unresolved_routes, *prebuilt.unresolved_routes}
    }
    node_tools = {agent_id: _capabilities_from_expr(expr, facts) for agent_id, expr in langgraph.node_tools.items()}
    return _attach_topology(framework_agents, topology_edges, {**langgraph.parent_ids, **prebuilt.parent_ids}, unresolved, node_tools)


def _attach_topology(
    agents: list[FrameworkAgent],
    topology_edges: list[FrameworkTopologyEdge],
    parent_ids: dict[str, str],
    unresolved_routes: dict[str, list[dict[str, Any]]],
    node_tools: dict[str, list[FrameworkCapability]],
) -> list[FrameworkAgent]:
    """Rebuild the frozen agents with their outgoing edges, nesting, unresolved routes and ToolNode tools."""
    if not topology_edges and not parent_ids and not unresolved_routes and not node_tools:
        return agents
    by_source: dict[str, list[FrameworkTopologyEdge]] = {}
    seen: set[tuple[str, str, str, str, str]] = set()
    for edge in topology_edges:
        key = (edge.source_id, edge.target_id, edge.relationship, edge.evidence, edge.branch)
        if key in seen:  # the same declaration repeated is one edge; the first line is kept
            continue
        seen.add(key)
        by_source.setdefault(edge.source_id, []).append(edge)
    rebuilt: list[FrameworkAgent] = []
    for agent in agents:
        unresolved = unresolved_routes.get(agent.stable_id, [])
        rebuilt.append(
            replace(
                agent,
                topology_edges=by_source.get(agent.stable_id, []),
                capabilities=_dedupe_capabilities([*agent.capabilities, *node_tools.get(agent.stable_id, [])]),
                parent_id=parent_ids.get(agent.stable_id, agent.parent_id),
                unresolved_routes=unresolved,
                dynamic_edges=agent.dynamic_edges or bool(unresolved),
            )
        )
    return rebuilt


def _agent_from_call(
    node: ast.Call,
    imports: set[str],
    rel_path: str,
    credential_refs: list[str],
    facts: _SourceFacts,
    *,
    fallback_name: str = "",
) -> FrameworkAgent | None:
    call_name = _call_name(node.func)
    short_name = call_name.split(".")[-1]
    short_name = facts.aliases.get(short_name, short_name)
    framework = _framework_for_call(imports, call_name, short_name)
    if framework is None:
        return None
    return FrameworkAgent(
        framework=framework,
        name=_agent_name(node, rel_path, framework, fallback_name=fallback_name),
        file_path=rel_path,
        line_number=getattr(node, "lineno", 1),
        capabilities=_dedupe_capabilities(_extract_capabilities(node, short_name, facts)),
        model_refs=_dedupe_strings(_extract_model_refs(node, short_name, facts)),
        credential_refs=credential_refs,
        dynamic_edges=_has_dynamic_edges(node),
        confidence="high" if short_name in _AGENT_CALLS or "assistants.create" in call_name else "medium",
    )


def _call_aliases(tree: ast.Module) -> dict[str, str]:
    """``from langgraph.graph import StateGraph as SG`` maps ``SG`` back to ``StateGraph``."""
    roots = {root for import_roots in _FRAMEWORK_IMPORTS.values() for root in import_roots}
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.split(".")[0] in roots:
            aliases.update({alias.asname: alias.name for alias in node.names if alias.asname and alias.name in _AGENT_CALLS})
    return aliases


def _detect_frameworks(tree: ast.Module, filepath: Path, root: Path, declared: frozenset[str] = frozenset()) -> set[str]:
    frameworks: set[str] = set()
    for node in ast.walk(tree):
        roots: list[str] = []
        if isinstance(node, ast.Import):
            roots.extend(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.append(node.module.split(".")[0])
        for framework, import_roots in _FRAMEWORK_IMPORTS.items():
            packages = _FRAMEWORK_PACKAGES.get(framework, ())
            if any(name in import_roots and is_sdk_import(name, packages, filepath, root, declared) for name in roots):
                frameworks.add(framework)
    return frameworks


def _framework_for_call(imports: set[str], call_name: str, short_name: str) -> str | None:
    if short_name not in _AGENT_CALLS and "assistants.create" not in call_name:
        return None
    if "assistants.create" in call_name and "openai-assistants" in imports:
        return "openai-assistants"
    if (short_name == "StateGraph" or short_name in ORCHESTRATOR_CALLS) and "langgraph" in imports:
        return "langgraph"
    if short_name in {"AssistantAgent", "UserProxyAgent", "ConversableAgent"} and "autogen" in imports:
        return "autogen"
    if short_name == "GroupChat" and "autogen" in imports:
        return "autogen"
    if short_name in {"Crew", "Agent"} and "crewai" in imports:
        return "crewai"
    if short_name in {"Agent", "create_react_agent", "create_agent", "create_openai_functions_agent", "AgentExecutor"}:
        for framework in _FRAMEWORK_PRIORITY:
            if framework in imports:
                return framework
    return None


def _decorator_name(node: ast.AST) -> str:
    """Dotted name of a decorator, unwrapping the applied form ``@mcp.tool()``."""
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    return _call_name(node)


def _collect_tools(tree: ast.Module) -> dict[str, FrameworkCapability]:
    tools: dict[str, FrameworkCapability] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                if is_agent_tool_decorator(_decorator_name(decorator)):
                    tools[node.name] = FrameworkCapability(node.name, "decorator", node.lineno, "high")
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    capability = _tool_from_expr(node.value, getattr(node, "lineno", 1))
                    if capability:
                        tools[target.id] = capability
        elif isinstance(node, ast.Call):
            short_name = _call_name(node.func).split(".")[-1]
            if short_name in _TOOL_REGISTRATION_CALLS and node.args:
                name = _name_from_expr(node.args[0]) or short_name
                tools[name] = FrameworkCapability(name, short_name, getattr(node, "lineno", 1), "medium", dynamic=True)
    return tools


def _extract_capabilities(node: ast.Call, short_name: str, facts: _SourceFacts) -> list[FrameworkCapability]:
    capabilities: list[FrameworkCapability] = []
    tools_node = _keyword_value(node, "tools")
    if tools_node is None and short_name in _AGENT_TOOLS_ARG and len(node.args) >= 2:
        tools_node = node.args[1]
    capabilities.extend(_capabilities_from_expr(tools_node, facts))
    if short_name == "StateGraph":
        capabilities.append(FrameworkCapability("state-graph", "graph-constructor", getattr(node, "lineno", 1), "medium", True))
    return capabilities


def _capabilities_from_expr(node: ast.AST | None, facts: _SourceFacts, *, _expanded: bool = False) -> list[FrameworkCapability]:
    if node is None:
        return []
    if isinstance(node, ast.Name):
        if not _expanded and node.id in facts.lists:
            return _capabilities_from_expr(facts.lists[node.id], facts, _expanded=True)
        return [facts.tools.get(node.id, FrameworkCapability(node.id, "name-reference", getattr(node, "lineno", 1), "low"))]
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [FrameworkCapability(node.value, "literal-tool-name", getattr(node, "lineno", 1), "medium")]
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        capabilities: list[FrameworkCapability] = []
        for item in node.elts:
            capabilities.extend(_capabilities_from_expr(item, facts, _expanded=_expanded))
        return capabilities
    if isinstance(node, ast.Dict):
        tool_type = _dict_value(node, "type")
        function_name = _dict_nested_value(node, "function", "name")
        name = function_name or tool_type
        if name:
            return [FrameworkCapability(name, "tool-dict", getattr(node, "lineno", 1), "medium")]
    if isinstance(node, ast.Call):
        capability = _tool_from_expr(node, getattr(node, "lineno", 1))
        return [capability] if capability else []
    return []


def _tool_from_expr(node: ast.AST, line_number: int) -> FrameworkCapability | None:
    if not isinstance(node, ast.Call):
        return None
    short_name = _call_name(node.func).split(".")[-1]
    if short_name not in _TOOL_CALLS:
        return None
    name = _string_keyword(node, "name")
    if not name and node.args:
        name = _name_from_expr(node.args[0])
    return FrameworkCapability(name or short_name, "tool-constructor", line_number, "medium")


def _extract_model_refs(node: ast.Call, short_name: str, facts: _SourceFacts) -> list[str]:
    """Literal model names, or a module-level chat-model binding passed by name."""
    values = [_keyword_value(node, keyword) for keyword in ("model", "model_name", "llm")]
    if short_name in _AGENT_TOOLS_ARG and node.args:
        values.append(node.args[0])
    refs = []
    for value in values:
        ref = _string_literal(value) or (facts.models.get(value.id, "") if isinstance(value, ast.Name) else "")
        if ref:
            refs.append(ref)
    return refs


def _extract_credential_refs(tree: ast.Module) -> list[str]:
    refs: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call_name = _call_name(node.func)
            if call_name in {"os.getenv", "getenv", "os.environ.get"} and node.args:
                value = _string_literal(node.args[0])
                if value and is_credential_key(value):
                    refs.append(value)
        elif isinstance(node, ast.Subscript) and _call_name(node.value) == "os.environ":
            value = _string_literal(node.slice)
            if value and is_credential_key(value):
                refs.append(value)
    return _dedupe_strings(refs)


def _agent_name(node: ast.Call, rel_path: str, framework: str, *, fallback_name: str = "") -> str:
    for keyword in ("name", "role") if fallback_name else ("name", "role", "supervisor_name"):
        value = _string_keyword(node, keyword)
        if value:
            return value
    if fallback_name:
        return fallback_name
    if node.args:
        value = _string_literal(node.args[0])
        if value:
            return value
    return f"{Path(rel_path).stem}:{framework}:{getattr(node, 'lineno', 1)}"


def _collect_topology_edges(
    tree: ast.Module,
    rel_path: str,
    agent_by_binding: dict[str, FrameworkAgent],
    agent_by_line: dict[int, FrameworkAgent],
) -> list[FrameworkTopologyEdge]:
    """Crew and GroupChat membership edges; LangGraph wiring lives in ``langgraph_topology``."""
    edges: list[FrameworkTopologyEdge] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        short_name = _call_name(node.func).split(".")[-1]
        if short_name not in {"Crew", "GroupChat"}:
            continue
        line_number = getattr(node, "lineno", 1)
        source = agent_by_line.get(line_number)
        members = _agents_from_expr(_keyword_value(node, "agents"), agent_by_binding)
        if source:
            for member in members:
                edges.append(_topology_edge(source, member, "delegated_to", rel_path, line_number, f"{short_name}(agents=[...])", "high"))
        for left, right in _member_pairs(members):
            edges.append(_topology_edge(left, right, "shares_server", rel_path, line_number, f"shared {short_name} membership", "medium"))
    return edges


def _topology_edge(
    source: FrameworkAgent,
    target: FrameworkAgent,
    relationship: str,
    file_path: str,
    line_number: int,
    evidence: str,
    confidence: str,
) -> FrameworkTopologyEdge:
    return FrameworkTopologyEdge(
        source_id=source.stable_id,
        source_name=source.name,
        target_id=target.stable_id,
        target_name=target.name,
        relationship=relationship,
        file_path=file_path,
        line_number=line_number,
        framework=source.framework,
        evidence=evidence,
        confidence=confidence,
    )


def _agents_from_expr(node: ast.AST | None, agent_by_binding: dict[str, FrameworkAgent]) -> list[FrameworkAgent]:
    if not isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return []
    agents: list[FrameworkAgent] = []
    for item in node.elts:
        if isinstance(item, ast.Name) and item.id in agent_by_binding:
            agents.append(agent_by_binding[item.id])
    return agents


def _member_pairs(agents: list[FrameworkAgent]) -> list[tuple[FrameworkAgent, FrameworkAgent]]:
    pairs: list[tuple[FrameworkAgent, FrameworkAgent]] = []
    for index, left in enumerate(agents):
        for right in agents[index + 1 :]:
            pairs.append((left, right))
    return pairs


def _first_target_name(targets: list[ast.expr]) -> str:
    for target in targets:
        if isinstance(target, ast.Name):
            return target.id
    return ""


def _has_dynamic_edges(node: ast.Call) -> bool:
    tools_node = _keyword_value(node, "tools")
    if tools_node is None:
        return False
    return not isinstance(tools_node, (ast.List, ast.Tuple, ast.Set))


def _keyword_value(node: ast.Call, name: str) -> ast.AST | None:
    for kw in node.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _string_keyword(node: ast.Call, name: str) -> str:
    return _string_literal(_keyword_value(node, name))


def _string_literal(node: ast.AST | None) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


def _name_from_expr(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _dict_value(node: ast.Dict, key: str) -> str:
    for dict_key, dict_value in zip(node.keys, node.values, strict=False):
        if _string_literal(dict_key) == key:
            return _string_literal(dict_value)
    return ""


def _dict_nested_value(node: ast.Dict, key: str, nested_key: str) -> str:
    for dict_key, dict_value in zip(node.keys, node.values, strict=False):
        if _string_literal(dict_key) == key and isinstance(dict_value, ast.Dict):
            return _dict_value(dict_value, nested_key)
    return ""


def _dedupe_capabilities(capabilities: list[FrameworkCapability]) -> list[FrameworkCapability]:
    seen: set[str] = set()
    deduped: list[FrameworkCapability] = []
    for capability in capabilities:
        if capability.name in seen:
            continue
        seen.add(capability.name)
        deduped.append(capability)
    return deduped


def _dedupe_strings(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))
