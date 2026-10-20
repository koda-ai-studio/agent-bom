"""Per-file Python entrypoint, guardrail and sink extraction."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from agent_bom.ast.python_semantics import (
    _DYNAMIC_CODE_CALLS,
    _FILE_MUTATION_CALLS,
    _FRAMEWORK_IMPORTS,
    _GUARDRAIL_IMPORTS,
    _MAX_FILE_SIZE,
    _SUBPROCESS_CALLS,
    _build_parent_map,
    _call_argument_expr,
    _call_references_sensitive_credential_path,
    _expr_is_dynamic_or_tracked,
    _import_matches_module,
    _is_command_execution_call_name,
    _is_guarded_call,
    _is_http_client_call_name,
    _is_path_access_call_name,
    _is_privilege_escalation_call_name,
    _is_shell_execution_call,
    _is_sql_call_name,
    _is_unsafe_deserialization_call_name,
    _module_name_for_rel_path,
    _open_mode_is_mutating,
    _target_names,
    _uses_safe_yaml_loader,
)
from agent_bom.ast.python_structure import _build_function_cfg_edges as _build_function_cfg_edges
from agent_bom.ast.python_structure import _call_name as _call_name
from agent_bom.ast.python_structure import _collect_python_import_aliases as _collect_python_import_aliases
from agent_bom.ast.python_structure import _extract_params as _extract_params
from agent_bom.ast.python_structure import _extract_python_prompts as _extract_python_prompts
from agent_bom.ast.python_structure import _get_return_annotation as _get_return_annotation
from agent_bom.ast.python_tools import (
    _MCP_DISPATCH_SEGMENTS,
    _collect_framework_tool_registrations,
    _get_decorator_name,
    _has_list_tools_handler,
    _list_tools_declarations,
    _source_imports_mcp_module,
)
from agent_bom.ast.source_reader import parse_python_source, read_source_for_analysis
from agent_bom.ast.sql_safety import FunctionSqlScope, ModuleSqlFacts
from agent_bom.ast.sql_safety import expr_uses_dynamic_string as _expr_uses_dynamic_string
from agent_bom.ast_models import DetectedGuardrail, ExtractedPrompt, FlowFinding, ToolSignature, _FunctionAnalysis, _PythonToolRegistration
from agent_bom.ast_signal_utils import _GUARDRAIL_CALL_PATTERNS
from agent_bom.ast_signal_utils import is_agent_tool_decorator as _is_agent_tool_decorator


@dataclass(frozen=True)
class _PythonFileContext:
    """Per-file facts every function in a Python file is analyzed against."""

    rel_path: str
    parent_map: dict[ast.AST, ast.AST]
    current_module: str
    imported_modules: dict[str, str]
    imported_functions: dict[str, tuple[str, str]]
    registrations_by_handler: dict[str, _PythonToolRegistration]
    low_level_tools: list[tuple[str, int]]
    sql: ModuleSqlFacts


def _import_frameworks_and_guardrails(tree: ast.Module, rel_path: str) -> tuple[list[str], list[DetectedGuardrail]]:
    """Detect agent frameworks and guardrail libraries from import statements."""
    frameworks: list[str] = []
    guardrails: list[DetectedGuardrail] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        # ``import a, b`` binds every alias; keeping only the last one made
        # detection depend on where the guardrail sat in the list.
        modules = [alias.name for alias in node.names] if isinstance(node, ast.Import) else [node.module or ""]
        for module in modules:
            for framework_module, framework_name in _FRAMEWORK_IMPORTS.items():
                if _import_matches_module(module, framework_module) and framework_name not in frameworks:
                    frameworks.append(framework_name)
            for guard_module, (name, gtype) in _GUARDRAIL_IMPORTS.items():
                if _import_matches_module(module, guard_module):
                    guardrails.append(
                        DetectedGuardrail(
                            name=name,
                            guardrail_type=gtype,
                            file_path=rel_path,
                            line_number=node.lineno,
                            framework=name,
                            description=f"Imported from {module}",
                        )
                    )
    return frameworks, guardrails


def _low_level_tool_signatures(tree: ast.Module, rel_path: str) -> tuple[list[tuple[str, int]], list[ToolSignature]]:
    """Tools a low-level ``Server`` declares in its ListTools handler."""
    low_level_tools: list[tuple[str, int]] = []
    if _source_imports_mcp_module(tree) and _has_list_tools_handler(tree):
        low_level_tools = _list_tools_declarations(tree)
    signatures = [
        ToolSignature(
            name=tool_name,
            parameters=[],
            return_type="unknown",
            description="Python MCP low-level ListTools declaration",
            file_path=rel_path,
            line_number=tool_line,
            decorators=["tools/list"],
            is_async=False,
        )
        for tool_name, tool_line in low_level_tools
    ]
    return low_level_tools, signatures


def _decorator_tool_flags(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[list[str], bool, bool]:
    """Return ``(decorator names, is decorated tool, is MCP dispatch handler)``."""
    decorators: list[str] = []
    is_decorated_tool = False
    is_dispatch_handler = False
    for dec in node.decorator_list:
        dec_name = _get_decorator_name(dec)
        if dec_name:
            decorators.append(dec_name)
            if _is_agent_tool_decorator(dec_name):
                is_decorated_tool = True
            if dec_name.rsplit(".", 1)[-1] in _MCP_DISPATCH_SEGMENTS:
                is_dispatch_handler = True
    return decorators, is_decorated_tool, is_dispatch_handler


def _python_tool_signature(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    ctx: _PythonFileContext,
    decorators: list[str],
    registration: _PythonToolRegistration | None,
    entrypoint_name: str,
) -> ToolSignature:
    docstring = ast.get_docstring(node) or ""
    return ToolSignature(
        name=entrypoint_name,
        parameters=_extract_params(node),
        return_type=_get_return_annotation(node),
        description=docstring[:300],
        file_path=ctx.rel_path,
        line_number=node.lineno,
        decorators=decorators,
        is_async=isinstance(node, ast.AsyncFunctionDef),
        handler=node.name if registration else "",
        registration_kind="framework_tool" if registration else "",
        framework=registration.framework if registration else "",
        provenance=registration.provenance if registration else "",
    )


def _python_function_analysis(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    ctx: _PythonFileContext,
) -> tuple[ToolSignature | None, _FunctionAnalysis, list[FlowFinding]]:
    """Analyze one function: its tool signature, call/CFG facts and local sink findings."""
    decorators, is_decorated_tool, is_dispatch_handler = _decorator_tool_flags(node)
    registration = ctx.registrations_by_handler.get(node.name)
    # ``@server.call_tool()`` dispatches to every tool; it is not itself
    # one. Suppressing its signature only once the real names are known
    # means a server whose names are built dynamically keeps the signal
    # it has today rather than going silent.
    is_tool_signature = registration is not None or (is_decorated_tool and not (is_dispatch_handler and ctx.low_level_tools))
    entrypoint_name = registration.tool_name if registration else node.name
    signature = _python_tool_signature(node, ctx, decorators, registration, entrypoint_name) if is_tool_signature else None
    func_info = _FunctionAnalysis(
        qualified_name=f"{ctx.rel_path}:{node.name}",
        simple_name=node.name,
        file_path=ctx.rel_path,
        line_number=node.lineno,
        is_tool=is_decorated_tool or registration is not None,
        module_name=ctx.current_module,
        param_names=[arg.arg for arg in node.args.args if arg.arg != "self"],
        node=node,
        parent_map=ctx.parent_map,
        cfg_edges=_build_function_cfg_edges(node, ctx.rel_path),
        imported_modules=dict(ctx.imported_modules),
        imported_functions=dict(ctx.imported_functions),
        entrypoint_name=entrypoint_name,
        entrypoint_kind="framework_tool" if registration else "mcp_tool",
        entrypoint_framework=registration.framework if registration else "",
        entrypoint_provenance=registration.provenance if registration else "",
    )
    return signature, func_info, _function_call_findings(node, func_info, ctx)


def _dynamic_string_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Names assigned a dynamically built string anywhere in the function."""
    names: set[str] = set()
    for inner_stmt in ast.walk(node):
        if isinstance(inner_stmt, ast.Assign) and _expr_uses_dynamic_string(inner_stmt.value):
            for target in inner_stmt.targets:
                names.update(_target_names(target))
        elif isinstance(inner_stmt, ast.AnnAssign) and _expr_uses_dynamic_string(inner_stmt.value):
            names.update(_target_names(inner_stmt.target))
    return names


_LOCAL_SINK_TITLES = {
    "unguarded_tool_sink": "Tool entrypoint reaches dangerous sink without validation",
    "credential_file_access": "Tool entrypoint reads a credential file",
    "privilege_escalation": "Tool entrypoint can assume another identity",
    "unsafe_deserialization": "Unsafe deserialization primitive detected",
    "command_string_construction": "Shell command is built through string interpolation",
    "ssrf_url_construction": "Outbound URL is built through string interpolation",
    "sql_string_construction": "SQL query is built through string interpolation",
}


def _function_call_findings(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    func_info: _FunctionAnalysis,
    ctx: _PythonFileContext,
) -> list[FlowFinding]:
    """Record every call in the function and the local sink findings each one raises."""
    dynamic_string_names = _dynamic_string_names(node)
    sql_scope = ctx.sql.for_function(node)
    entrypoint = func_info.entrypoint_name
    findings: list[FlowFinding] = []
    for inner in ast.walk(node):
        if not isinstance(inner, ast.Call):
            continue
        call_name = _call_name(inner.func)
        line_number = getattr(inner, "lineno", node.lineno)
        if call_name:
            func_info.called_names.append((call_name, line_number))
        matches = _tool_call_matches(inner, call_name, line_number, func_info, ctx)
        matches.extend(_string_construction_matches(inner, call_name, ctx.rel_path, dynamic_string_names, sql_scope))
        findings.extend(
            FlowFinding(
                category=category,
                title=_LOCAL_SINK_TITLES[category],
                detail=detail,
                file_path=ctx.rel_path,
                line_number=line_number,
                entrypoint=entrypoint,
                sink=call_name,
                call_path=[entrypoint, call_name],
            )
            for category, detail in matches
        )
    return findings


def _tool_call_matches(
    inner: ast.Call,
    call_name: str,
    line_number: int,
    func_info: _FunctionAnalysis,
    ctx: _PythonFileContext,
) -> list[tuple[str, str]]:
    """Dangerous-call bookkeeping plus the sinks only a tool entrypoint reports."""
    tool = f"Tool `{func_info.entrypoint_name}` in {ctx.rel_path}"
    matches: list[tuple[str, str]] = []
    is_file_mutation = call_name in _FILE_MUTATION_CALLS and (call_name != "open" or _open_mode_is_mutating(inner))
    if call_name in _DYNAMIC_CODE_CALLS or call_name in _SUBPROCESS_CALLS or is_file_mutation:
        guarded = _is_guarded_call(inner, ctx.parent_map)
        func_info.dangerous_calls.append((call_name, line_number, guarded))
        if func_info.is_tool and not guarded:
            detail = f"{tool} calls `{call_name}` without an obvious validation or authorization branch."
            matches.append(("unguarded_tool_sink", detail))
    if not func_info.is_tool or not call_name:
        return matches
    if _is_path_access_call_name(call_name) and _call_references_sensitive_credential_path(inner):
        matches.append(("credential_file_access", f"{tool} reads a known credential-file location."))
    if _is_privilege_escalation_call_name(call_name):
        matches.append(("privilege_escalation", f"{tool} calls an identity-assumption API."))
    return matches


def _string_construction_matches(
    inner: ast.Call,
    call_name: str,
    rel_path: str,
    dynamic_string_names: set[str],
    sql_scope: FunctionSqlScope,
) -> list[tuple[str, str]]:
    """Unsafe deserialization and string-built command, URL and SQL sinks in any function."""
    matches: list[tuple[str, str]] = []
    if _is_unsafe_deserialization_call_name(call_name) and not _uses_safe_yaml_loader(inner):
        detail = f"{rel_path} calls `{call_name}` which can deserialize attacker-controlled content without a safe loader."
        matches.append(("unsafe_deserialization", detail))
    built = f"{rel_path} builds"
    if _is_command_execution_call_name(call_name) and _is_shell_execution_call(call_name, inner):
        command_expr = _call_argument_expr(inner, primary_arg_names={"args", "command"})
        if _expr_is_dynamic_or_tracked(command_expr, dynamic_string_names):
            detail = f"{built} a shell command dynamically before calling `{call_name}`, which is a common command injection pattern."
            matches.append(("command_string_construction", detail))
    if _is_http_client_call_name(call_name):
        url_expr = _call_argument_expr(inner, primary_arg_names={"url", "uri", "endpoint"})
        if _expr_is_dynamic_or_tracked(url_expr, dynamic_string_names):
            detail = f"{built} an outbound URL dynamically before calling `{call_name}`, which is a common SSRF pattern."
            matches.append(("ssrf_url_construction", detail))
    if _is_sql_call_name(call_name) and sql_scope.query_is_unsafe(inner):
        detail = f"{built} a SQL query dynamically before calling `{call_name}`, which is a common SQL injection pattern."
        matches.append(("sql_string_construction", detail))
    return matches


def _regex_guardrails(source: str, rel_path: str, guardrails: list[DetectedGuardrail]) -> list[DetectedGuardrail]:
    """Guardrail calls found by the source regex fallback, skipping lines imports already reported."""
    found: list[DetectedGuardrail] = []
    for match in _GUARDRAIL_CALL_PATTERNS.finditer(source):
        line_num = source[: match.start()].count("\n") + 1
        guard_name = match.group(0)
        if not any(g.line_number == line_num for g in [*guardrails, *found]):
            found.append(
                DetectedGuardrail(
                    name=guard_name,
                    guardrail_type="content_filter",
                    file_path=rel_path,
                    line_number=line_num,
                    framework="generic",
                    description=f"Function/method call: {guard_name}",
                )
            )
    return found


def _analyze_file(
    file_path: Path,
    rel_path: str,
) -> tuple[
    list[ExtractedPrompt],
    list[DetectedGuardrail],
    list[ToolSignature],
    list[str],
    list[_FunctionAnalysis],
    list[FlowFinding],
]:
    """Analyze a single Python file with full AST parsing."""
    source = read_source_for_analysis(file_path, rel_path, scanner="ast-python", max_size=_MAX_FILE_SIZE)
    if source is None:
        return [], [], [], [], [], []

    try:
        tree = parse_python_source(source, filename=str(file_path))
    except SyntaxError:
        return [], [], [], [], [], []

    current_module = _module_name_for_rel_path(rel_path)
    imported_modules, imported_functions = _collect_python_import_aliases(
        tree,
        current_module=current_module,
        rel_path=rel_path,
    )
    registrations = _collect_framework_tool_registrations(tree, imported_modules, imported_functions)
    frameworks, guardrails = _import_frameworks_and_guardrails(tree, rel_path)
    prompts = _extract_python_prompts(tree, rel_path)
    low_level_tools, tools = _low_level_tool_signatures(tree, rel_path)
    ctx = _PythonFileContext(
        rel_path=rel_path,
        parent_map=_build_parent_map(tree),
        current_module=current_module,
        imported_modules=imported_modules,
        imported_functions=imported_functions,
        registrations_by_handler={registration.handler_name: registration for registration in registrations},
        low_level_tools=low_level_tools,
        sql=ModuleSqlFacts.from_source(tree, source),
    )

    function_analyses: list[_FunctionAnalysis] = []
    flow_findings: list[FlowFinding] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            signature, func_info, function_findings = _python_function_analysis(node, ctx)
            if signature is not None:
                tools.append(signature)
            function_analyses.append(func_info)
            flow_findings.extend(function_findings)

    guardrails.extend(_regex_guardrails(source, rel_path, guardrails))
    return prompts, guardrails, tools, frameworks, function_analyses, flow_findings
