"""Python framework tool registration and MCP declarations."""

from __future__ import annotations

import ast

from agent_bom.ast.python_semantics import (
    _FRAMEWORK_AGENT_CONSTRUCTORS,
    _FRAMEWORK_TOOL_CONSTRUCTORS,
    _FRAMEWORK_TOOL_HANDLER_KEYWORDS,
    _FRAMEWORK_TOOL_ROOTS,
    _keyword_value,
)
from agent_bom.ast.python_structure import _call_name as _call_name
from agent_bom.ast.python_structure import _extract_string_value as _extract_string_value
from agent_bom.ast_models import _PythonToolRegistration


def _framework_for_imported_call(
    call: ast.Call,
    imported_modules: dict[str, str],
    imported_functions: dict[str, tuple[str, str]],
) -> str:
    """Resolve a constructor's framework from explicit import evidence."""
    call_name = _call_name(call.func)
    head = call_name.split(".", 1)[0]
    imported = imported_functions.get(head)
    module_name = imported[0] if imported else imported_modules.get(head, "")
    root = module_name.split(".", 1)[0]
    return _FRAMEWORK_TOOL_ROOTS.get(root, "")


def _canonical_imported_call_name(
    call: ast.Call,
    imported_functions: dict[str, tuple[str, str]],
) -> str:
    """Return a call name with a directly imported alias resolved."""
    call_name = _call_name(call.func)
    head, separator, tail = call_name.partition(".")
    imported = imported_functions.get(head)
    if imported is None:
        return call_name
    symbol = imported[1]
    return f"{symbol}.{tail}" if separator and tail else symbol


def _module_assignments(tree: ast.Module) -> dict[str, ast.expr]:
    assignments: dict[str, ast.expr] = {}
    for statement in tree.body:
        if isinstance(statement, ast.Assign):
            for target in statement.targets:
                if isinstance(target, ast.Name):
                    assignments[target.id] = statement.value
        elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name) and statement.value is not None:
            assignments[statement.target.id] = statement.value
    return assignments


def _resolve_framework_tool_exprs(
    node: ast.expr | None,
    assignments: dict[str, ast.expr],
    *,
    depth: int = 0,
) -> list[tuple[str, ast.Call]]:
    """Resolve a static tools collection to constructor calls and bindings."""
    if node is None or depth > 6:
        return []
    if isinstance(node, ast.Name):
        assigned = assignments.get(node.id)
        if assigned is None:
            return []
        if isinstance(assigned, ast.Call):
            return [(node.id, assigned)]
        return _resolve_framework_tool_exprs(assigned, assignments, depth=depth + 1)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        resolved: list[tuple[str, ast.Call]] = []
        for item in node.elts:
            resolved.extend(_resolve_framework_tool_exprs(item, assignments, depth=depth + 1))
        return resolved
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return [
            *_resolve_framework_tool_exprs(node.left, assignments, depth=depth + 1),
            *_resolve_framework_tool_exprs(node.right, assignments, depth=depth + 1),
        ]
    if isinstance(node, ast.Call):
        return [("inline", node)]
    return []


def _framework_tool_from_call(
    binding: str,
    call: ast.Call,
    *,
    framework: str,
    agent_constructor: str,
    index: int,
    imported_modules: dict[str, str],
    imported_functions: dict[str, tuple[str, str]],
    function_names: set[str],
) -> _PythonToolRegistration | None:
    call_name = _canonical_imported_call_name(call, imported_functions)
    short_name = call_name.rsplit(".", 1)[-1]
    constructor_name = short_name
    handler_node: ast.expr | None = None

    if short_name == "from_function":
        owner = call_name.rsplit(".", 1)[0].rsplit(".", 1)[-1]
        if owner not in _FRAMEWORK_TOOL_CONSTRUCTORS:
            return None
        constructor_name = f"{owner}.from_function"
        if call.args:
            handler_node = call.args[0]
    elif short_name in _FRAMEWORK_TOOL_CONSTRUCTORS:
        for keyword_name in _FRAMEWORK_TOOL_HANDLER_KEYWORDS:
            handler_node = _keyword_value(call, keyword_name)
            if handler_node is not None:
                break
        if handler_node is None and short_name == "Tool" and len(call.args) >= 2:
            handler_node = call.args[1]
    else:
        return None

    constructor_framework = _framework_for_imported_call(call, imported_modules, imported_functions)
    if not constructor_framework:
        # ``StructuredTool.from_function`` resolves through the imported owner,
        # not the terminal method name.
        owner = call_name.split(".", 1)[0]
        imported = imported_functions.get(owner)
        module_name = imported[0] if imported else imported_modules.get(owner, "")
        constructor_framework = _FRAMEWORK_TOOL_ROOTS.get(module_name.split(".", 1)[0], "")
    if not constructor_framework or not isinstance(handler_node, ast.Name) or handler_node.id not in function_names:
        return None

    tool_name = ""
    name_node = _keyword_value(call, "name")
    if name_node is not None:
        tool_name = _extract_string_value(name_node) or ""
    if not tool_name and call.args and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
        tool_name = call.args[0].value
    if not tool_name:
        tool_name = handler_node.id
    tool_name = tool_name.strip()
    if not tool_name:
        return None

    provenance = f"python:{framework}:{agent_constructor}.tools[{index}]:{binding}->{constructor_name}(func={handler_node.id})"
    return _PythonToolRegistration(
        tool_name=tool_name,
        handler_name=handler_node.id,
        framework=framework,
        provenance=provenance,
    )


def _collect_framework_tool_registrations(
    tree: ast.Module,
    imported_modules: dict[str, str],
    imported_functions: dict[str, tuple[str, str]],
) -> list[_PythonToolRegistration]:
    """Collect only tools statically wired to a recognized framework agent."""
    assignments = _module_assignments(tree)
    function_names = {node.name for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    registrations: list[_PythonToolRegistration] = []
    seen: set[tuple[str, str, str]] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        agent_constructor = _canonical_imported_call_name(node, imported_functions).rsplit(".", 1)[-1]
        if agent_constructor not in _FRAMEWORK_AGENT_CONSTRUCTORS:
            continue
        framework = _framework_for_imported_call(node, imported_modules, imported_functions)
        if not framework:
            continue
        tools_node = _keyword_value(node, "tools")
        # LangChain's constructors have different positional signatures:
        # initialize_agent(tools, llm), the create_* helpers (llm, tools, ...).
        tools_position = {"initialize_agent": 0, "create_react_agent": 1, "create_openai_functions_agent": 1}.get(agent_constructor)
        if tools_node is None and tools_position is not None and len(node.args) > tools_position:
            tools_node = node.args[tools_position]
        for index, (binding, tool_call) in enumerate(_resolve_framework_tool_exprs(tools_node, assignments)):
            registration = _framework_tool_from_call(
                binding,
                tool_call,
                framework=framework,
                agent_constructor=agent_constructor,
                index=index,
                imported_modules=imported_modules,
                imported_functions=imported_functions,
                function_names=function_names,
            )
            if registration is None:
                continue
            key = (registration.tool_name, registration.handler_name, registration.provenance)
            if key not in seen:
                seen.add(key)
                registrations.append(registration)
    return registrations


def _imported_module_names(tree: ast.Module) -> list[str]:
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.append(node.module or "")
    return names


def _source_imports_mcp_module(tree: ast.Module) -> bool:
    """Return whether the file imports an MCP SDK module.

    Whole dotted segments only, so ``mcp.server.lowlevel`` and
    ``modelcontextprotocol.server`` resolve while a project-local
    ``mcp_client_utils`` or ``mcpherson.tools`` does not.
    """
    for module in _imported_module_names(tree):
        if any(segment.lower() in _MCP_ROOT_MODULES for segment in module.split(".") if segment):
            return True
    return False


def _decorator_last_segment(node: ast.expr) -> str:
    """Last dotted segment of a decorator, unwrapping the applied form ``@x.y()``."""
    return (_get_decorator_name(node) or "").rsplit(".", 1)[-1]


def _has_list_tools_handler(tree: ast.Module) -> bool:
    """Return whether the file wires a low-level ListTools handler.

    Both SDK generations count: v1 registers the handler with a
    ``@server.list_tools()`` decorator (bare or applied), v2 passes it to the
    ``Server`` constructor as ``on_list_tools=``.
    """
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if any(_decorator_last_segment(dec) == _MCP_LIST_TOOLS_SEGMENT for dec in node.decorator_list):
                return True
        elif isinstance(node, ast.Call):
            if any(kw.arg == _MCP_LIST_TOOLS_KEYWORD for kw in node.keywords):
                return True
    return False


def _list_tools_declarations(tree: ast.Module) -> list[tuple[str, int]]:
    """Return ``(tool_name, line_number)`` for every ``types.Tool(name="…")``."""
    declarations: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or _call_name(node.func).rsplit(".", 1)[-1] != "Tool":
            continue
        for keyword in node.keywords:
            # A non-literal name cannot be resolved statically; guessing one
            # would put a fabricated tool in the inventory.
            if keyword.arg != "name" or not isinstance(keyword.value, ast.Constant):
                continue
            name = keyword.value.value
            if not isinstance(name, str) or not name.strip():
                continue
            entry = (name.strip(), node.lineno)
            if entry in seen:
                continue
            seen.add(entry)
            declarations.append(entry)
    return declarations


def _get_decorator_name(node: ast.expr) -> str | None:
    """Extract decorator name from AST node."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parts = []
        current: ast.expr = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    if isinstance(node, ast.Call):
        return _get_decorator_name(node.func)
    return None


_MCP_ROOT_MODULES = frozenset({"mcp", "modelcontextprotocol"})


_MCP_LIST_TOOLS_SEGMENT = "list_tools"


_MCP_LIST_TOOLS_KEYWORD = "on_list_tools"


_MCP_DISPATCH_SEGMENTS = frozenset({_MCP_LIST_TOOLS_SEGMENT, "call_tool"})
