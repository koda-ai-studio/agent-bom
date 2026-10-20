"""Python call graph and bounded taint analysis."""

from __future__ import annotations

import ast
import os
from collections.abc import Callable
from importlib import import_module
from typing import Any

from agent_bom.ast.python_file_analysis import _analyze_file as _analyze_file
from agent_bom.ast.python_semantics import (
    _DANGEROUS_CALLS,
    _DYNAMIC_CODE_CALLS,
    _application_entrypoint_matches,
    _branch_definitely_exits,
    _expr_contains_validation_hint,
    _is_command_execution_call_name,
    _is_guarded_call,
    _is_http_client_call_name,
    _is_llm_call_name,
    _is_path_access_call_name,
    _is_request_data_attribute,
    _is_sanitizer_call_name,
    _is_shell_execution_call,
    _is_sql_call_name,
    _is_untrusted_source_call,
    _is_xss_sink_call_name,
    _names_in_expr,
    _request_global_is_framework_source,
    _returns_boolean_constant,
    _route_tainted_params,
    _target_names,
    _validation_source_names_from_expr,
)
from agent_bom.ast.python_semantics import _SKIP_DIRS as _SKIP_DIRS
from agent_bom.ast.python_semantics import _SKIP_FILE_PATTERNS as _SKIP_FILE_PATTERNS
from agent_bom.ast.python_structure import _call_name as _call_name
from agent_bom.ast_models import ApplicationEntrypoint, CallEdge, DependencySymbolReach, FlowFinding, _FunctionAnalysis


def _max_taint_depth() -> int:
    raw = os.environ.get("AGENT_BOM_TAINT_MAX_DEPTH", "").strip()
    if not raw:
        return 4
    try:
        value = int(raw)
    except ValueError:
        return 4
    # Clamp to a sane operational range. Going deeper than 8 in practice
    # explodes the visit-set and produces near-duplicate findings; going
    # below 2 disables the inter-procedural pass entirely.
    return max(2, min(value, 8))


def _build_flow_finding(
    *,
    category: str,
    title: str,
    detail: str,
    file_path: str,
    line_number: int,
    entrypoint: str,
    sink: str,
    call_path: list[str],
    source: str = "",
) -> FlowFinding:
    return FlowFinding(
        category=category,
        title=title,
        detail=detail,
        file_path=file_path,
        line_number=line_number,
        entrypoint=entrypoint,
        sink=sink,
        call_path=call_path,
        source=source,
    )


def _resolve_called_function(
    caller: _FunctionAnalysis,
    raw_name: str,
    by_name: dict[str, list[_FunctionAnalysis]],
    by_module_and_name: dict[tuple[str, str], _FunctionAnalysis],
) -> _FunctionAnalysis | None:
    """Resolve a call target using same-file preference, then unique global match."""
    imported_target = caller.imported_functions.get(raw_name)
    if imported_target:
        resolved = by_module_and_name.get(imported_target)
        if resolved is not None:
            return resolved

    for alias, module_name in sorted(caller.imported_modules.items(), key=lambda item: len(item[0]), reverse=True):
        if not raw_name.startswith(f"{alias}."):
            continue
        target_name = raw_name[len(alias) + 1 :].split(".")[-1]
        resolved = by_module_and_name.get((module_name, target_name))
        if resolved is not None:
            return resolved

    simple_name = raw_name.split(".")[-1]
    candidates = by_name.get(simple_name, [])
    if not candidates:
        return None

    same_file = [candidate for candidate in candidates if candidate.file_path == caller.file_path]
    if len(same_file) == 1:
        return same_file[0]
    if len(candidates) == 1:
        return candidates[0]
    return None


def _resolve_external_dependency_symbol(caller: _FunctionAnalysis, raw_name: str) -> tuple[str, str, str] | None:
    """Resolve an imported dependency call to ``(package, module, symbol)``.

    This is intentionally conservative: it reports only explicit imports
    visible in the scanned source file. It does not infer dynamic imports,
    package metadata, or type-dispatched calls.
    """
    if not raw_name:
        return None
    if raw_name in caller.imported_functions:
        module_name, symbol = caller.imported_functions[raw_name]
        package = module_name.split(".", 1)[0]
        return package, module_name, symbol

    head, _, tail = raw_name.partition(".")
    imported_target = caller.imported_functions.get(head)
    if imported_target and tail:
        module_name, symbol = imported_target
        package = module_name.split(".", 1)[0]
        return package, module_name, f"{symbol}.{tail}"

    for alias, module_name in sorted(caller.imported_modules.items(), key=lambda item: len(item[0]), reverse=True):
        if raw_name == alias:
            package = module_name.split(".", 1)[0]
            return package, module_name, module_name.rsplit(".", 1)[-1]
        if not raw_name.startswith(f"{alias}."):
            continue
        symbol = raw_name[len(alias) + 1 :]
        if not symbol:
            continue
        package = module_name.split(".", 1)[0]
        return package, module_name, symbol
    return None


_TAINT_SINK_TITLES = {
    "tainted_path_access": "Untrusted data reaches a file-system path sink",
    "tainted_ssrf_sink": "Untrusted data reaches an outbound URL sink",
    "tainted_command_execution": "Untrusted data reaches shell command execution",
    "tainted_dynamic_code_execution": "Untrusted data reaches dynamic code execution",
    "tainted_dangerous_sink": "Untrusted data reaches a dangerous sink",
    "tainted_xss_sink": "Untrusted data reaches an HTML rendering sink",
    "tainted_sql_query": "Untrusted data reaches SQL execution",
    "tainted_llm_prompt": "Untrusted data reaches an LLM invocation",
}


_TaintResult = tuple[bool, list[FlowFinding]]


_StatementResult = tuple[list[FlowFinding], bool]


def _taint_sink_categories(call_name: str, call: ast.Call) -> tuple[str, ...]:
    """Classify a call as the taint sink categories it reports, first match wins."""
    if _is_path_access_call_name(call_name):
        return ("tainted_path_access",)
    if _is_http_client_call_name(call_name):
        return ("tainted_ssrf_sink",)
    if _is_command_execution_call_name(call_name) and _is_shell_execution_call(call_name, call):
        if call_name in _DANGEROUS_CALLS:
            return ("tainted_command_execution", "tainted_dangerous_sink")
        return ("tainted_command_execution",)
    if call_name in _DYNAMIC_CODE_CALLS:
        return ("tainted_dynamic_code_execution",)
    if call_name in _DANGEROUS_CALLS:
        return ("tainted_dangerous_sink",)
    if _is_xss_sink_call_name(call_name):
        return ("tainted_xss_sink",)
    if _is_sql_call_name(call_name):
        return ("tainted_sql_query",)
    if _is_llm_call_name(call_name):
        return ("tainted_llm_prompt",)
    return ()


def _taint_expr_children(expr: ast.AST) -> list[ast.AST | None] | None:
    """Sub-expressions whose taint an aggregate expression unions, in evaluation order."""
    if isinstance(expr, ast.JoinedStr):
        return list(expr.values)
    if isinstance(expr, ast.BinOp):
        return [expr.left, expr.right]
    if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        return list(expr.elts)
    if isinstance(expr, ast.Dict):
        return [child for key, value in zip(expr.keys, expr.values, strict=False) for child in (key, value)]
    if isinstance(expr, ast.BoolOp):
        return list(expr.values)
    if isinstance(expr, ast.Compare):
        return [expr.left, *expr.comparators]
    return None


def _names_bound_to_params(callee: _FunctionAnalysis, call: ast.Call, params: set[str]) -> set[str]:
    """Names passed, positionally or by keyword, into ``params`` of ``callee``."""
    names: set[str] = set()
    for param_name, arg in zip(callee.param_names, call.args, strict=False):
        if param_name in params:
            names.update(_names_in_expr(arg))
    for keyword in call.keywords:
        if keyword.arg and keyword.arg in params:
            names.update(_names_in_expr(keyword.value))
    return names


def _returns_opposite_booleans(first: list[ast.stmt], second: list[ast.stmt]) -> bool:
    return (_returns_boolean_constant(first, True) and _returns_boolean_constant(second, False)) or (
        _returns_boolean_constant(first, False) and _returns_boolean_constant(second, True)
    )


def _validated_by_boolean_if(func: _FunctionAnalysis, statement: ast.If) -> set[str]:
    """Parameters an ``if check(x): return True else: return False`` validates."""
    if not _expr_contains_validation_hint(statement.test):
        return set()
    branch_validated = {name for name in _validation_source_names_from_expr(statement.test) if name in func.param_names}
    if branch_validated and _returns_opposite_booleans(statement.body, statement.orelse):
        return branch_validated
    return set()


def _validated_by_early_return(func: _FunctionAnalysis, body_statements: list[ast.stmt]) -> set[str]:
    """Parameters validated by a top-level ``if`` whose early return mirrors the tail."""
    validated: set[str] = set()
    for index, statement in enumerate(body_statements):
        if not isinstance(statement, ast.If) or not _expr_contains_validation_hint(statement.test):
            continue
        branch_validated = {name for name in _validation_source_names_from_expr(statement.test) if name in func.param_names}
        if branch_validated and _returns_opposite_booleans(statement.body, body_statements[index + 1 :]):
            validated.update(branch_validated)
    return validated


class _TaintInterpreter:
    """Inter-procedural taint walk from tool and HTTP route entrypoints into sinks.

    Holds the state shared across every analyzed function: the call-resolution
    indexes, the validator summary cache and the depth cap. Each function
    invocation runs in its own ``_TaintFrame``.
    """

    def __init__(self, functions: list[_FunctionAnalysis]) -> None:
        self.by_name: dict[str, list[_FunctionAnalysis]] = {}
        self.by_module_and_name: dict[tuple[str, str], _FunctionAnalysis] = {}
        for func in functions:
            self.by_name.setdefault(func.simple_name, []).append(func)
            if func.module_name:
                self.by_module_and_name[(func.module_name, func.simple_name)] = func
        self.validator_summary_cache: dict[str, set[str]] = {}
        self.max_depth = _max_taint_depth()

    def resolve(self, func: _FunctionAnalysis, call_name: str) -> _FunctionAnalysis | None:
        if not call_name:
            return None
        return _resolve_called_function(func, call_name, self.by_name, self.by_module_and_name)

    def validator_param_names(self, func: _FunctionAnalysis, seen: set[str] | None = None) -> set[str]:
        cached = self.validator_summary_cache.get(func.qualified_name)
        if cached is not None:
            return cached
        if func.node is None:
            self.validator_summary_cache[func.qualified_name] = set()
            return set()

        seen = set(seen or ())
        if func.qualified_name in seen:
            return set()
        seen.add(func.qualified_name)

        validated: set[str] = set()
        for statement in ast.walk(func.node):
            if isinstance(statement, ast.Return):
                validated.update(self._validated_by_return(func, statement, seen))
            elif isinstance(statement, ast.If):
                validated.update(_validated_by_boolean_if(func, statement))
        validated.update(_validated_by_early_return(func, list(func.node.body)))

        self.validator_summary_cache[func.qualified_name] = validated
        return validated

    def _validated_by_return(self, func: _FunctionAnalysis, statement: ast.Return, seen: set[str]) -> set[str]:
        value = statement.value
        if value is not None and _expr_contains_validation_hint(value):
            return {name for name in _validation_source_names_from_expr(value) if name in func.param_names}
        if not isinstance(value, ast.Call):
            return set()
        callee = self.resolve(func, _call_name(value.func))
        if callee is None:
            return set()
        callee_validated = self.validator_param_names(callee, seen)
        return {name for name in _names_bound_to_params(callee, value, callee_validated) if name in func.param_names}

    def guarded_names_from_expr(self, func: _FunctionAnalysis, expr: ast.AST | None) -> set[str]:
        if expr is None:
            return set()
        if _expr_contains_validation_hint(expr):
            return _validation_source_names_from_expr(expr)
        if isinstance(expr, ast.Call):
            callee = self.resolve(func, _call_name(expr.func))
            if callee is None:
                return set()
            return _names_bound_to_params(callee, expr, self.validator_param_names(callee))
        if isinstance(expr, ast.BoolOp):
            guarded_names: set[str] = set()
            for value in expr.values:
                guarded_names.update(self.guarded_names_from_expr(func, value))
            return guarded_names
        if isinstance(expr, ast.UnaryOp):
            return self.guarded_names_from_expr(func, expr.operand)
        return set()

    def post_if_guarded_names(self, func: _FunctionAnalysis, statement: ast.If) -> set[str]:
        """Return names guarded on the path that continues after an if-statement."""
        test = statement.test
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            guarded = self.guarded_names_from_expr(func, test.operand)
            if guarded and _branch_definitely_exits(statement.body):
                return guarded
            return set()

        guarded = self.guarded_names_from_expr(func, test)
        if guarded and _branch_definitely_exits(statement.orelse):
            return guarded
        return set()

    def analyze_function(
        self,
        func: _FunctionAnalysis,
        tainted_params: set[str],
        call_path: list[str],
        visited: set[tuple[str, tuple[str, ...]]],
    ) -> tuple[list[FlowFinding], bool]:
        # Bounded inter-procedural traversal: the visit-set already prevents
        # cycles, but a long fan-out chain could still explode the work
        # without surfacing a finding the operator can act on. Cap the
        # call_path length so the analyzer commits to a documented depth.
        if len(call_path) > self.max_depth:
            return [], False
        visit_key = (func.qualified_name, tuple(sorted(tainted_params)))
        if visit_key in visited or func.node is None:
            return [], False
        visited = set(visited)
        visited.add(visit_key)

        frame = _TaintFrame(self, func, set(tainted_params), call_path, visited)
        _, findings, returns_tainted = frame.walk_statements(func.node.body, set())
        return findings, returns_tainted

    def run(
        self,
        functions: list[_FunctionAnalysis],
        application_entrypoints: list[ApplicationEntrypoint] | None,
    ) -> list[FlowFinding]:
        roots: list[tuple[_FunctionAnalysis, set[str], str]] = [
            (func, set(func.param_names), func.entrypoint_name or func.simple_name)
            for func in functions
            if func.is_tool and func.param_names
        ]
        tool_ids = {func.qualified_name for func, _, _ in roots}
        for _, entry, func in _application_entrypoint_matches(functions, application_entrypoints, kinds=frozenset({"http_route"})):
            if func.qualified_name not in tool_ids:
                roots.append((func, _route_tainted_params(func), entry.name))

        seen_findings: set[tuple[str, str, str, int, str]] = set()
        aggregated_findings: list[FlowFinding] = []
        for func, tainted_params, entrypoint in roots:
            tool_findings, _ = self.analyze_function(func, tainted_params, [entrypoint], set())
            for finding in tool_findings:
                dedup_key = (finding.category, finding.file_path, finding.sink, finding.line_number, finding.entrypoint)
                if dedup_key in seen_findings:
                    continue
                seen_findings.add(dedup_key)
                aggregated_findings.append(finding)
        return aggregated_findings


class _TaintFrame:
    """Taint state for one function invocation on one inter-procedural call path."""

    def __init__(
        self,
        interpreter: _TaintInterpreter,
        func: _FunctionAnalysis,
        tainted_vars: set[str],
        call_path: list[str],
        visited: set[tuple[str, tuple[str, ...]]],
    ) -> None:
        self.interpreter = interpreter
        self.func = func
        self.tainted_vars = tainted_vars
        self.call_path = call_path
        self.visited = visited
        self.request_global_is_source = _request_global_is_framework_source(func)

    def expr_taint(self, expr: ast.AST | None, current_sanitized: set[str]) -> _TaintResult:
        if expr is None:
            return False, []
        if isinstance(expr, ast.Name):
            return expr.id in self.tainted_vars and expr.id not in current_sanitized, []
        if isinstance(expr, ast.Constant):
            return False, []
        if isinstance(expr, ast.Attribute):
            if self.request_global_is_source and _is_request_data_attribute(expr):
                return True, []
            return self.expr_taint(expr.value, current_sanitized)
        if isinstance(expr, (ast.Subscript, ast.FormattedValue)):
            return self.expr_taint(expr.value, current_sanitized)
        if isinstance(expr, ast.Call):
            return self.call_taint(expr, current_sanitized)
        children = _taint_expr_children(expr)
        if children is not None:
            return self._union_taint(children, current_sanitized)
        return any(name in self.tainted_vars and name not in current_sanitized for name in _names_in_expr(expr)), []

    def _union_taint(self, children: list[ast.AST | None], current_sanitized: set[str]) -> _TaintResult:
        findings: list[FlowFinding] = []
        tainted = False
        for child in children:
            child_tainted, child_findings = self.expr_taint(child, current_sanitized)
            findings.extend(child_findings)
            tainted |= child_tainted
        return tainted, findings

    def call_taint(self, call: ast.Call, current_sanitized: set[str]) -> _TaintResult:
        call_name = _call_name(call.func)
        arg_results = [self.expr_taint(arg, current_sanitized) for arg in call.args]
        kw_results = [(kw.arg, *self.expr_taint(kw.value, current_sanitized)) for kw in call.keywords]
        receiver_tainted = False
        receiver_findings: list[FlowFinding] = []
        if isinstance(call.func, ast.Attribute):
            receiver_tainted, receiver_findings = self.expr_taint(call.func.value, current_sanitized)

        arg_tainted = receiver_tainted or any(result[0] for result in arg_results) or any(result[1] for result in kw_results)
        nested_findings: list[FlowFinding] = []
        nested_findings.extend(receiver_findings)
        for _, child_findings in arg_results:
            nested_findings.extend(child_findings)
        for _, _, child_findings in kw_results:
            nested_findings.extend(child_findings)

        if _is_untrusted_source_call(call_name):
            return True, nested_findings
        if _is_sanitizer_call_name(call_name):
            return False, nested_findings

        source_label = self._source_label(call, receiver_tainted, arg_results, current_sanitized)
        if call_name and arg_tainted and not _is_guarded_call(call, self.func.parent_map):
            nested_findings.extend(self._sink_findings(call, call_name, source_label))
        return self._propagate_into_callee(call_name, arg_results, kw_results, nested_findings)

    def _source_label(
        self,
        call: ast.Call,
        receiver_tainted: bool,
        arg_results: list[_TaintResult],
        current_sanitized: set[str],
    ) -> str:
        source_names: set[str] = set()
        if receiver_tainted and isinstance(call.func, ast.Attribute):
            source_names.update(name for name in _names_in_expr(call.func.value) if name in self.tainted_vars)
        for arg, (is_tainted, _) in zip(call.args, arg_results, strict=False):
            if is_tainted:
                source_names.update(name for name in _names_in_expr(arg) if name in self.tainted_vars)
        for kw in call.keywords:
            kw_tainted, _ = self.expr_taint(kw.value, current_sanitized)
            if kw_tainted:
                source_names.update(name for name in _names_in_expr(kw.value) if name in self.tainted_vars)
        return ", ".join(sorted(source_names)) or "untrusted input"

    def _sink_findings(self, call: ast.Call, call_name: str, source_label: str) -> list[FlowFinding]:
        func = self.func
        line_number = getattr(call, "lineno", func.line_number)
        findings: list[FlowFinding] = []
        for category in _taint_sink_categories(call_name, call):
            shell = " with shell execution" if category == "tainted_command_execution" else ""
            findings.append(
                _build_flow_finding(
                    category=category,
                    title=_TAINT_SINK_TITLES[category],
                    detail=f"Untrusted data ({source_label}) reaches `{call_name}`{shell} in {func.file_path}.",
                    file_path=func.file_path,
                    line_number=line_number,
                    entrypoint=self.call_path[0],
                    sink=call_name,
                    call_path=self.call_path + [call_name],
                    source=source_label,
                )
            )
        return findings

    def _propagate_into_callee(
        self,
        call_name: str,
        arg_results: list[_TaintResult],
        kw_results: list[tuple[str | None, bool, list[FlowFinding]]],
        nested_findings: list[FlowFinding],
    ) -> _TaintResult:
        callee = self.interpreter.resolve(self.func, call_name)
        if callee is None:
            return False, nested_findings
        callee_tainted_params: set[str] = set()
        for param_name, (is_tainted, _) in zip(callee.param_names, arg_results, strict=False):
            if is_tainted:
                callee_tainted_params.add(param_name)
        for kw_name, is_tainted, _ in kw_results:
            if kw_name and is_tainted and kw_name in callee.param_names:
                callee_tainted_params.add(kw_name)
        if not callee_tainted_params:
            return False, nested_findings
        sub_findings, callee_returns_tainted = self.interpreter.analyze_function(
            callee,
            callee_tainted_params,
            self.call_path + [callee.simple_name],
            self.visited,
        )
        nested_findings.extend(sub_findings)
        return callee_returns_tainted, nested_findings

    def walk_statements(self, statements: list[ast.stmt], current_sanitized: set[str]) -> tuple[set[str], list[FlowFinding], bool]:
        local_tainted = set(self.tainted_vars)
        findings: list[FlowFinding] = []
        returns_tainted = False
        for statement in statements:
            handler = _TAINT_STATEMENT_HANDLERS.get(type(statement))
            if handler is None:
                continue
            statement_findings, statement_returns_tainted = handler(self, statement, current_sanitized, local_tainted)
            findings.extend(statement_findings)
            returns_tainted |= statement_returns_tainted
        return local_tainted, findings, returns_tainted

    def _bind(self, target_names: set[str], value_tainted: bool, current_sanitized: set[str], local_tainted: set[str]) -> None:
        if value_tainted:
            local_tainted.update(target_names)
            self.tainted_vars.update(target_names)
        else:
            local_tainted.difference_update(target_names)
            self.tainted_vars.difference_update(target_names)
            current_sanitized.difference_update(target_names)

    def _mark_tainted(self, names: set[str], local_tainted: set[str]) -> None:
        self.tainted_vars.update(names)
        local_tainted.update(names)

    def _walk_assign(self, statement: ast.Assign, current_sanitized: set[str], local_tainted: set[str]) -> _StatementResult:
        value_tainted, findings = self.expr_taint(statement.value, current_sanitized)
        target_names: set[str] = set()
        for target in statement.targets:
            target_names.update(_target_names(target))
        self._bind(target_names, value_tainted, current_sanitized, local_tainted)
        return findings, False

    def _walk_ann_assign(self, statement: ast.AnnAssign, current_sanitized: set[str], local_tainted: set[str]) -> _StatementResult:
        value_tainted, findings = self.expr_taint(statement.value, current_sanitized)
        self._bind(_target_names(statement.target), value_tainted, current_sanitized, local_tainted)
        return findings, False

    def _walk_aug_assign(self, statement: ast.AugAssign, current_sanitized: set[str], local_tainted: set[str]) -> _StatementResult:
        target_names = _target_names(statement.target)
        value_tainted, findings = self.expr_taint(statement.value, current_sanitized)
        target_tainted = any(name in self.tainted_vars for name in target_names)
        if value_tainted or target_tainted:
            local_tainted.update(target_names)
            self.tainted_vars.update(target_names)
        return findings, False

    def _walk_expr(self, statement: ast.Expr, current_sanitized: set[str], local_tainted: set[str]) -> _StatementResult:
        _, findings = self.expr_taint(statement.value, current_sanitized)
        return findings, False

    def _walk_assert(self, statement: ast.Assert, current_sanitized: set[str], local_tainted: set[str]) -> _StatementResult:
        _, findings = self.expr_taint(statement.test, current_sanitized)
        current_sanitized.update(self.interpreter.guarded_names_from_expr(self.func, statement.test))
        return findings, False

    def _walk_return(self, statement: ast.Return, current_sanitized: set[str], local_tainted: set[str]) -> _StatementResult:
        returns_tainted, findings = self.expr_taint(statement.value, current_sanitized)
        return findings, returns_tainted

    def _walk_if(self, statement: ast.If, current_sanitized: set[str], local_tainted: set[str]) -> _StatementResult:
        _, findings = self.expr_taint(statement.test, current_sanitized)
        guarded_names = self.interpreter.guarded_names_from_expr(self.func, statement.test)
        body_tainted, body_findings, body_returns_tainted = self.walk_statements(statement.body, current_sanitized | guarded_names)
        orelse_tainted, orelse_findings, orelse_returns_tainted = self.walk_statements(statement.orelse, set(current_sanitized))
        findings.extend(body_findings)
        findings.extend(orelse_findings)
        self._mark_tainted(body_tainted | orelse_tainted, local_tainted)
        current_sanitized.update(self.interpreter.post_if_guarded_names(self.func, statement))
        return findings, body_returns_tainted or orelse_returns_tainted

    def _walk_loop(
        self,
        statement: ast.For | ast.AsyncFor | ast.While,
        current_sanitized: set[str],
        local_tainted: set[str],
    ) -> _StatementResult:
        iter_expr = statement.iter if isinstance(statement, (ast.For, ast.AsyncFor)) else statement.test
        iter_tainted, findings = self.expr_taint(iter_expr, current_sanitized)
        body_sanitized = set(current_sanitized)
        if isinstance(statement, (ast.For, ast.AsyncFor)) and iter_tainted:
            tainted_loop_names = _target_names(statement.target)
            body_sanitized.difference_update(tainted_loop_names)
            self.tainted_vars.update(tainted_loop_names)
        body_tainted, body_findings, body_returns_tainted = self.walk_statements(statement.body, body_sanitized)
        orelse_tainted, orelse_findings, orelse_returns_tainted = self.walk_statements(statement.orelse, set(current_sanitized))
        findings.extend(body_findings)
        findings.extend(orelse_findings)
        self._mark_tainted(body_tainted | orelse_tainted, local_tainted)
        return findings, body_returns_tainted or orelse_returns_tainted

    def _walk_with(self, statement: ast.With, current_sanitized: set[str], local_tainted: set[str]) -> _StatementResult:
        findings: list[FlowFinding] = []
        for item in statement.items:
            context_tainted, context_findings = self.expr_taint(item.context_expr, current_sanitized)
            findings.extend(context_findings)
            if context_tainted and item.optional_vars is not None:
                self._mark_tainted(_target_names(item.optional_vars), local_tainted)
        body_tainted, body_findings, body_returns_tainted = self.walk_statements(statement.body, set(current_sanitized))
        findings.extend(body_findings)
        self._mark_tainted(body_tainted, local_tainted)
        return findings, body_returns_tainted

    def _walk_try(self, statement: ast.Try, current_sanitized: set[str], local_tainted: set[str]) -> _StatementResult:
        branch_tainted, findings, returns_tainted = self.walk_statements(statement.body, set(current_sanitized))
        branch_tainted = set(branch_tainted)
        blocks = [handler.body for handler in statement.handlers] + [statement.orelse, statement.finalbody]
        for block in blocks:
            block_tainted, block_findings, block_returns_tainted = self.walk_statements(block, set(current_sanitized))
            findings.extend(block_findings)
            branch_tainted.update(block_tainted)
            returns_tainted |= block_returns_tainted
        self._mark_tainted(branch_tainted, local_tainted)
        return findings, returns_tainted


_TAINT_STATEMENT_HANDLERS: dict[type[ast.stmt], Callable[[_TaintFrame, Any, set[str], set[str]], _StatementResult]] = {
    ast.Assign: _TaintFrame._walk_assign,
    ast.AnnAssign: _TaintFrame._walk_ann_assign,
    ast.AugAssign: _TaintFrame._walk_aug_assign,
    ast.Expr: _TaintFrame._walk_expr,
    ast.Assert: _TaintFrame._walk_assert,
    ast.If: _TaintFrame._walk_if,
    ast.For: _TaintFrame._walk_loop,
    ast.AsyncFor: _TaintFrame._walk_loop,
    ast.While: _TaintFrame._walk_loop,
    ast.With: _TaintFrame._walk_with,
    ast.Try: _TaintFrame._walk_try,
    ast.Return: _TaintFrame._walk_return,
}


def _build_taint_findings(
    functions: list[_FunctionAnalysis],
    application_entrypoints: list[ApplicationEntrypoint] | None = None,
) -> list[FlowFinding]:
    """Build taint/data-flow findings from tool and HTTP route entrypoints into sinks and LLM calls."""
    return _TaintInterpreter(functions).run(functions, application_entrypoints)


def _find_call_node(func: _FunctionAnalysis, call_name: str, line_number: int) -> ast.Call | None:
    """Locate the ``ast.Call`` node ``func.called_names`` recorded (name, line).

    ``called_names`` only stores the resolved call name and line — this walks
    ``func.node`` the same way that collection did (see the ``ast.walk`` loop
    that builds ``called_names``) to recover the actual call expression so its
    arguments can be inspected for taint.
    """
    if func.node is None:
        return None
    for inner in ast.walk(func.node):
        if isinstance(inner, ast.Call) and getattr(inner, "lineno", None) == line_number and _call_name(inner.func) == call_name:
            return inner
    return None


def _call_has_tainted_argument(func: _FunctionAnalysis, call: ast.Call) -> bool | None:
    """Track straight-line local argument flow within one function boundary.

    True records any argument derived from a parameter or untrusted primitive;
    it does not identify a vulnerable parameter or prove external exploitability.
    False means no such flow in the supported expressions. Unsupported control
    flow, external values and missing syntax remain unassessed (None).
    """
    if func.node is None:
        return None
    arguments = func.node.args
    parameters = [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]
    parameters += [arg for arg in (arguments.vararg, arguments.kwarg) if arg is not None]
    values: dict[str, bool | None] = {arg.arg: True for arg in parameters}

    def expression(expr: ast.AST) -> bool | None:
        if isinstance(expr, ast.Constant):
            return False
        if isinstance(expr, ast.Name):
            return values.get(expr.id)
        if isinstance(expr, ast.Call):
            name = _call_name(expr.func)
            if name and _is_untrusted_source_call(name):
                return True
            # Unknown callees may transform or sanitize their arguments.
            return None
        if isinstance(expr, (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp, ast.NamedExpr)):
            return None
        parts = [expression(child) for child in ast.iter_child_nodes(expr) if isinstance(child, ast.expr)]
        return True if True in parts else None if None in parts or not parts else False

    for statement in func.node.body:
        contains_call = any(node is call for node in ast.walk(statement))
        if contains_call:
            if not isinstance(statement, (ast.Assign, ast.AnnAssign, ast.Expr, ast.Return)):
                return None
            results = [expression(arg) for arg in [*call.args, *(kw.value for kw in call.keywords)]]
            return True if True in results else None if None in results else False
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            value = expression(statement.value) if statement.value is not None else None
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    values[target.id] = value
                else:
                    for name in ast.walk(target):
                        if isinstance(name, ast.Name) and isinstance(name.ctx, ast.Store):
                            values[name.id] = None
        else:
            # Assignments inside branches/loops cannot safely preserve an old
            # value. Do not visit nested function bodies as executed statements.
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                values[statement.name] = None
                continue
            for name in ast.walk(statement):
                if isinstance(name, ast.Name) and isinstance(name.ctx, (ast.Store, ast.Del)):
                    values[name.id] = None
    return None


def _build_dependency_symbol_reach(
    functions: list[_FunctionAnalysis],
    application_entrypoints: list[ApplicationEntrypoint] | None = None,
) -> list[DependencySymbolReach]:
    """Build bounded externally-invokable-root → dependency symbol evidence."""
    by_name: dict[str, list[_FunctionAnalysis]] = {}
    by_module_and_name: dict[tuple[str, str], _FunctionAnalysis] = {}
    for func in functions:
        by_name.setdefault(func.simple_name, []).append(func)
        if func.module_name:
            by_module_and_name[(func.module_name, func.simple_name)] = func

    adjacency: dict[str, list[_FunctionAnalysis]] = {func.qualified_name: [] for func in functions}
    for func in functions:
        for raw_name, _line_num in func.called_names:
            callee = _resolve_called_function(func, raw_name, by_name, by_module_and_name)
            if callee is not None:
                adjacency[func.qualified_name].append(callee)

    function_by_id = {func.qualified_name: func for func in functions}
    max_depth = _max_taint_depth()
    reached: list[DependencySymbolReach] = []
    seen: set[tuple[str, str, str, str, int]] = set()
    roots: list[tuple[str, _FunctionAnalysis, ApplicationEntrypoint | None]] = [
        (func.entrypoint_name or func.simple_name, func, None) for func in functions if func.is_tool
    ]
    for index, entry, matched in _application_entrypoint_matches(functions, application_entrypoints):
        roots.append((f"__application_entrypoint_{index}", matched, entry))

    for root_name, root, application_entrypoint in roots:
        exposed_root_name = root.entrypoint_name or root.simple_name
        queue: list[tuple[str, list[str]]] = [(root.qualified_name, [exposed_root_name])]
        visited: set[str] = set()
        while queue:
            current_id, path = queue.pop(0)
            if len(path) > max_depth:
                continue
            if current_id in visited:
                continue
            visited.add(current_id)
            current = function_by_id[current_id]
            for raw_name, line_num in current.called_names:
                external = _resolve_external_dependency_symbol(current, raw_name)
                if external is None:
                    continue
                package, module_name, symbol = external
                dedup_key = (root_name, module_name, symbol, current.file_path, line_num)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                call_node = _find_call_node(current, raw_name, line_num)
                tainted_argument = _call_has_tainted_argument(current, call_node) if call_node is not None else None
                reached.append(
                    DependencySymbolReach(
                        entrypoint=application_entrypoint.name if application_entrypoint else exposed_root_name,
                        package=package,
                        module=module_name,
                        symbol=symbol,
                        file_path=current.file_path,
                        line_number=line_num,
                        call_path=[
                            *([application_entrypoint.name, *path[1:]] if application_entrypoint else path),
                            f"{module_name}.{symbol}",
                        ],
                        depth=max(0, len(path) - 1),
                        entrypoint_kind=application_entrypoint.kind if application_entrypoint else root.entrypoint_kind,
                        entrypoint_framework=(application_entrypoint.framework if application_entrypoint else root.entrypoint_framework),
                        entrypoint_provenance=(application_entrypoint.provenance if application_entrypoint else root.entrypoint_provenance),
                        tainted_argument=tainted_argument,
                    )
                )
            for child in adjacency.get(current_id, []):
                queue.append((child.qualified_name, [*path, child.simple_name]))
    return reached


def _build_call_graph(functions: list[_FunctionAnalysis]) -> tuple[list[CallEdge], list[FlowFinding]]:
    """Build a lightweight call graph and bounded helper-chain findings.

    This path is intentionally lightweight: it follows resolved helper-call
    chains from tool entrypoints to already-detected dangerous sinks, but it
    does not claim full inter-procedural taint propagation or proof-grade
    reachability across arbitrary call graphs.
    """
    by_name: dict[str, list[_FunctionAnalysis]] = {}
    by_module_and_name: dict[tuple[str, str], _FunctionAnalysis] = {}
    for func in functions:
        by_name.setdefault(func.simple_name, []).append(func)
        if func.module_name:
            by_module_and_name[(func.module_name, func.simple_name)] = func

    adjacency: dict[str, list[_FunctionAnalysis]] = {func.qualified_name: [] for func in functions}
    edges: list[CallEdge] = []
    for func in functions:
        for raw_name, line_num in func.called_names:
            callee = _resolve_called_function(func, raw_name, by_name, by_module_and_name)
            if callee is None:
                continue
            adjacency[func.qualified_name].append(callee)
            edges.append(
                CallEdge(
                    caller=func.simple_name,
                    callee=callee.simple_name,
                    file_path=func.file_path,
                    line_number=line_num,
                )
            )

    findings: list[FlowFinding] = []
    seen_findings: set[tuple[str, str, str, int]] = set()
    function_by_id = {func.qualified_name: func for func in functions}
    max_depth = _max_taint_depth()
    for func in functions:
        if not func.is_tool:
            continue
        entrypoint_name = func.entrypoint_name or func.simple_name
        queue: list[tuple[str, list[str]]] = [(func.qualified_name, [entrypoint_name])]
        visited: set[str] = set()
        while queue:
            current_id, path = queue.pop(0)
            if len(path) > max_depth:
                # Stop following helper chains past the configured depth so
                # the bounded claim is honored uniformly across the two
                # taint surfaces (this BFS + the parameter-level recursion
                # in _build_taint_findings).
                continue
            if current_id in visited:
                continue
            visited.add(current_id)
            current = function_by_id[current_id]
            for sink_name, line_num, guarded in current.dangerous_calls:
                if guarded:
                    continue
                if len(path) <= 1:
                    continue
                dedup_key = (entrypoint_name, sink_name, current.file_path, line_num)
                if dedup_key in seen_findings:
                    continue
                seen_findings.add(dedup_key)
                findings.append(
                    FlowFinding(
                        category="interprocedural_dangerous_flow",
                        title="Tool helper chain reaches dangerous sink",
                        detail=(
                            f"Tool `{entrypoint_name}` reaches `{sink_name}` through a bounded helper-call chain in {current.file_path}."
                        ),
                        file_path=current.file_path,
                        line_number=line_num,
                        entrypoint=entrypoint_name,
                        sink=sink_name,
                        call_path=path + [sink_name],
                    )
                )
            for callee in adjacency.get(current_id, []):
                queue.append((callee.qualified_name, path + [callee.simple_name]))

    return edges, findings


_EXPORTS = {
    "_GUARDRAIL_IMPORTS": "agent_bom.ast.python_semantics",
    "_FRAMEWORK_IMPORTS": "agent_bom.ast.python_semantics",
    "_import_matches_module": "agent_bom.ast.python_semantics",
    "_SENSITIVE_CREDENTIAL_PATH_FRAGMENTS": "agent_bom.ast.python_semantics",
    "_SUBPROCESS_CALLS": "agent_bom.ast.python_semantics",
    "_FILE_MUTATION_CALLS": "agent_bom.ast.python_semantics",
    "_PATH_ACCESS_CALLS": "agent_bom.ast.python_semantics",
    "_HTTP_CLIENT_CALLS": "agent_bom.ast.python_semantics",
    "_SQL_CALLS": "agent_bom.ast.python_semantics",
    "_UNSAFE_DESERIALIZATION_CALLS": "agent_bom.ast.python_semantics",
    "_XSS_CALLS": "agent_bom.ast.python_semantics",
    "_LLM_CALL_SUBSTRINGS": "agent_bom.ast.python_semantics",
    "_UNTRUSTED_SOURCE_CALLS": "agent_bom.ast.python_semantics",
    "_REQUEST_GLOBAL_MODULES": "agent_bom.ast.python_semantics",
    "_REQUEST_DATA_ATTRIBUTES": "agent_bom.ast.python_semantics",
    "_INJECTED_DEPENDENCY_CALLS": "agent_bom.ast.python_semantics",
    "_SANITIZER_CALLS": "agent_bom.ast.python_semantics",
    "_SKIP_DIRS": "agent_bom.ast.python_semantics",
    "_SKIP_FILE_PATTERNS": "agent_bom.ast.python_semantics",
    "_MAX_FILE_SIZE": "agent_bom.ast.python_semantics",
    "_MAX_FILES": "agent_bom.ast.python_semantics",
    "_VALIDATION_HINTS": "agent_bom.ast.python_semantics",
    "_JS_TS_UNTRUSTED_DATA_RE": "agent_bom.ast.python_semantics",
    "_keyword_value": "agent_bom.ast.python_semantics",
    "_FRAMEWORK_TOOL_ROOTS": "agent_bom.ast.python_semantics",
    "_FRAMEWORK_AGENT_CONSTRUCTORS": "agent_bom.ast.python_semantics",
    "_FRAMEWORK_TOOL_CONSTRUCTORS": "agent_bom.ast.python_semantics",
    "_FRAMEWORK_TOOL_HANDLER_KEYWORDS": "agent_bom.ast.python_semantics",
    "_framework_for_imported_call": "agent_bom.ast.python_tools",
    "_canonical_imported_call_name": "agent_bom.ast.python_tools",
    "_module_assignments": "agent_bom.ast.python_tools",
    "_resolve_framework_tool_exprs": "agent_bom.ast.python_tools",
    "_framework_tool_from_call": "agent_bom.ast.python_tools",
    "_collect_framework_tool_registrations": "agent_bom.ast.python_tools",
    "_call_references_sensitive_credential_path": "agent_bom.ast.python_semantics",
    "_is_privilege_escalation_call_name": "agent_bom.ast.python_semantics",
    "_module_name_for_rel_path": "agent_bom.ast.python_semantics",
    "_open_mode_is_mutating": "agent_bom.ast.python_semantics",
    "_build_parent_map": "agent_bom.ast.python_semantics",
    "_is_unsafe_deserialization_call_name": "agent_bom.ast.python_semantics",
    "_uses_safe_yaml_loader": "agent_bom.ast.python_semantics",
    "_call_keyword_bool": "agent_bom.ast.python_semantics",
    "_call_argument_expr": "agent_bom.ast.python_semantics",
    "_expr_is_dynamic_or_tracked": "agent_bom.ast.python_semantics",
    "_PythonFileContext": "agent_bom.ast.python_file_analysis",
    "_import_frameworks_and_guardrails": "agent_bom.ast.python_file_analysis",
    "_low_level_tool_signatures": "agent_bom.ast.python_file_analysis",
    "_decorator_tool_flags": "agent_bom.ast.python_file_analysis",
    "_python_tool_signature": "agent_bom.ast.python_file_analysis",
    "_python_function_analysis": "agent_bom.ast.python_file_analysis",
    "_dynamic_string_names": "agent_bom.ast.python_file_analysis",
    "_LOCAL_SINK_TITLES": "agent_bom.ast.python_file_analysis",
    "_function_call_findings": "agent_bom.ast.python_file_analysis",
    "_tool_call_matches": "agent_bom.ast.python_file_analysis",
    "_string_construction_matches": "agent_bom.ast.python_file_analysis",
    "_regex_guardrails": "agent_bom.ast.python_file_analysis",
    "_analyze_file": "agent_bom.ast.python_file_analysis",
    "_MCP_ROOT_MODULES": "agent_bom.ast.python_tools",
    "_MCP_LIST_TOOLS_SEGMENT": "agent_bom.ast.python_tools",
    "_MCP_LIST_TOOLS_KEYWORD": "agent_bom.ast.python_tools",
    "_MCP_DISPATCH_SEGMENTS": "agent_bom.ast.python_tools",
    "_imported_module_names": "agent_bom.ast.python_tools",
    "_source_imports_mcp_module": "agent_bom.ast.python_tools",
    "_decorator_last_segment": "agent_bom.ast.python_tools",
    "_has_list_tools_handler": "agent_bom.ast.python_tools",
    "_list_tools_declarations": "agent_bom.ast.python_tools",
    "_get_decorator_name": "agent_bom.ast.python_tools",
}


def __getattr__(name: str) -> Any:
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module), name)
    globals()[name] = value
    return value
