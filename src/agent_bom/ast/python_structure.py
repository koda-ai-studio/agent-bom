"""Ast python structure helpers."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from agent_bom.ast_models import (
    ControlFlowEdge,
    ExtractedPrompt,
)
from agent_bom.ast_signal_utils import check_prompt_risks as _check_prompt_risks
from agent_bom.ast_signal_utils import classify_prompt_type as _classify_prompt_type

# ── Prompt extraction patterns ───────────────────────────────────────────────

# Field names that are NOT system prompts — excluded from prompt detection
# to prevent false positives on common documentation/UI fields.
_NON_PROMPT_KEYS = frozenset(
    {
        "description",
        "help",
        "help_text",
        "__doc__",
        "title",
        "label",
        "placeholder",
        "tooltip",
        "error_message",
        "docstring",
    }
)

# Variable/parameter names that typically hold system prompts
_PROMPT_VAR_NAMES = (
    frozenset(
        {
            "system_prompt",
            "system_message",
            "instructions",
            "system_instructions",
            "system_content",
            "prefix",
            "suffix",
            "preamble",
            "context",
            "system",
            "prompt_template",
            "template",
            "system_template",
            "initial_message",
            "persona",
            "role_description",
        }
    )
    - _NON_PROMPT_KEYS
)

# Keyword argument names in agent/LLM constructors that hold prompts
_PROMPT_KWARG_NAMES = (
    frozenset(
        {
            "system_prompt",
            "instructions",
            "system_message",
            "system",
            "prefix",
            "preamble",
            "prompt",
            "template",
            "system_template",
            "instruction",
            "backstory",
            "goal",
            "role",
            "system_instruction",
            "safety_settings",
        }
    )
    - _NON_PROMPT_KEYS
)

_PROMPT_UNTRUSTED_INPUT_RE = re.compile(
    r"\b(?:user\w*|input|payload|message|content|query|prompt|instruction|body|request)\b",
    re.IGNORECASE,
)

# ── AST extraction ───────────────────────────────────────────────────────────


def _extract_string_value(node: ast.expr) -> str | None:
    """Extract string value from an AST node (str literal, f-string, joined)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        # f-string — extract the literal parts
        parts = []
        for val in node.values:
            if isinstance(val, ast.Constant) and isinstance(val.value, str):
                parts.append(val.value)
            else:
                parts.append("{...}")
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _extract_string_value(node.left)
        right = _extract_string_value(node.right)
        if left is not None or right is not None:
            left = left if left is not None else "{...}"
            right = right if right is not None else "{...}"
            return f"{left}{right}"
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        template = _extract_string_value(node.func.value)
        if template is not None:
            return template
    return None


def _expr_contains_untrusted_prompt_input(node: ast.AST) -> bool:
    """Return True when a prompt expression interpolates likely untrusted input."""
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and _PROMPT_UNTRUSTED_INPUT_RE.search(child.id):
            return True
        if isinstance(child, ast.Attribute):
            attr_name = _expr_name(child)
            if attr_name and _PROMPT_UNTRUSTED_INPUT_RE.search(attr_name):
                return True
        if isinstance(child, ast.Call):
            call_name = _call_name(child.func).lower()
            if call_name in {"input", "request.get_json", "request.args.get", "request.form.get"}:
                return True
    return False


def _call_name(node: ast.AST) -> str:
    """Return a dotted call name when possible."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    return ""


def _package_name_for_module(module_name: str, rel_path: str) -> str:
    if Path(rel_path).name == "__init__.py":
        return module_name
    if "." not in module_name:
        return ""
    return module_name.rsplit(".", 1)[0]


def _resolve_imported_module(module: str | None, level: int, current_module: str, rel_path: str) -> str:
    if level <= 0:
        return module or ""
    package_name = _package_name_for_module(current_module, rel_path)
    package_parts = package_name.split(".") if package_name else []
    trim = max(level - 1, 0)
    if trim:
        package_parts = package_parts[: max(0, len(package_parts) - trim)]
    resolved_parts = [*package_parts]
    if module:
        resolved_parts.append(module)
    return ".".join(part for part in resolved_parts if part)


def _collect_python_import_aliases(
    tree: ast.AST,
    *,
    current_module: str,
    rel_path: str,
) -> tuple[dict[str, str], dict[str, tuple[str, str]]]:
    imported_modules: dict[str, str] = {}
    imported_functions: dict[str, tuple[str, str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                visible_name = alias.asname or alias.name
                imported_modules[visible_name] = alias.name
        elif isinstance(node, ast.ImportFrom):
            resolved_module = _resolve_imported_module(node.module, node.level, current_module, rel_path)
            if not resolved_module:
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                visible_name = alias.asname or alias.name
                imported_functions[visible_name] = (resolved_module, alias.name)
    return imported_modules, imported_functions


def _cfg_node_id(rel_path: str, function_name: str, label: str) -> str:
    return f"{rel_path}:{function_name}:{label}"


def _stmt_cfg_node_id(rel_path: str, function_name: str, stmt: ast.stmt) -> str:
    return _cfg_node_id(rel_path, function_name, f"L{getattr(stmt, 'lineno', 0)}")


def _first_stmt_cfg_node_id(rel_path: str, function_name: str, statements: list[ast.stmt]) -> str | None:
    if not statements:
        return None
    return _stmt_cfg_node_id(rel_path, function_name, statements[0])


def _build_function_cfg_edges(func_node: ast.FunctionDef | ast.AsyncFunctionDef, rel_path: str) -> list[ControlFlowEdge]:
    """Build a coarse CFG for a function body."""
    builder = _FunctionCfg(rel_path, func_node.name)
    entry_id = _cfg_node_id(rel_path, func_node.name, "entry")
    if func_node.body:
        builder.add_edge(entry_id, _stmt_cfg_node_id(rel_path, func_node.name, func_node.body[0]), "entry")
        builder.walk_block(func_node.body, builder.exit_id)
    else:
        builder.add_edge(entry_id, builder.exit_id, "entry")
    return builder.edges


class _FunctionCfg:
    def __init__(self, rel_path: str, function_name: str) -> None:
        self.rel_path = rel_path
        self.function_name = function_name
        self.exit_id = _cfg_node_id(rel_path, function_name, "exit")
        self.edges: list[ControlFlowEdge] = []
        self.seen: set[tuple[str, str, str]] = set()

    def add_edge(self, source: str | None, target: str | None, edge_type: str) -> None:
        if not source or not target:
            return
        key = (source, target, edge_type)
        if key in self.seen:
            return
        self.seen.add(key)
        self.edges.append(
            ControlFlowEdge(source=source, target=target, edge_type=edge_type, file_path=self.rel_path, function_name=self.function_name)
        )

    def walk_block(self, statements: list[ast.stmt], next_node: str) -> None:
        for index, stmt in enumerate(statements):
            stmt_id = _stmt_cfg_node_id(self.rel_path, self.function_name, stmt)
            after_id = (
                _stmt_cfg_node_id(self.rel_path, self.function_name, statements[index + 1]) if index + 1 < len(statements) else next_node
            )
            if isinstance(stmt, ast.If):
                body_first = _first_stmt_cfg_node_id(self.rel_path, self.function_name, stmt.body) or after_id
                orelse_first = _first_stmt_cfg_node_id(self.rel_path, self.function_name, stmt.orelse) or after_id
                self.add_edge(stmt_id, body_first, "branch_true")
                self.add_edge(stmt_id, orelse_first, "branch_false")
                self.walk_block(stmt.body, after_id)
                self.walk_block(stmt.orelse, after_id)
                continue
            if isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
                loop_body_first = _first_stmt_cfg_node_id(self.rel_path, self.function_name, stmt.body)
                if loop_body_first:
                    self.add_edge(stmt_id, loop_body_first, "loop_true")
                    self.walk_block(stmt.body, stmt_id)
                self.add_edge(stmt_id, after_id, "loop_false")
                if stmt.orelse:
                    orelse_first = _first_stmt_cfg_node_id(self.rel_path, self.function_name, stmt.orelse) or after_id
                    self.add_edge(stmt_id, orelse_first, "loop_orelse")
                    self.walk_block(stmt.orelse, after_id)
                continue
            if isinstance(stmt, ast.Try):
                body_first = _first_stmt_cfg_node_id(self.rel_path, self.function_name, stmt.body) or after_id
                self.add_edge(stmt_id, body_first, "try_body")
                self.walk_block(stmt.body, after_id)
                for handler in stmt.handlers:
                    handler_first = _first_stmt_cfg_node_id(self.rel_path, self.function_name, handler.body) or after_id
                    self.add_edge(stmt_id, handler_first, "except")
                    self.walk_block(handler.body, after_id)
                if stmt.orelse:
                    orelse_first = _first_stmt_cfg_node_id(self.rel_path, self.function_name, stmt.orelse) or after_id
                    self.add_edge(stmt_id, orelse_first, "try_else")
                    self.walk_block(stmt.orelse, after_id)
                if stmt.finalbody:
                    final_first = _first_stmt_cfg_node_id(self.rel_path, self.function_name, stmt.finalbody) or after_id
                    self.add_edge(stmt_id, final_first, "finally")
                    self.walk_block(stmt.finalbody, after_id)
                continue
            if isinstance(stmt, ast.Return):
                self.add_edge(stmt_id, self.exit_id, "return")
                continue
            if isinstance(stmt, ast.Break):
                self.add_edge(stmt_id, next_node, "break")
                continue
            if isinstance(stmt, ast.Continue):
                self.add_edge(stmt_id, next_node, "continue")
                continue
            self.add_edge(stmt_id, after_id, "next")


def _expr_name(expr: ast.AST | None) -> str:
    if expr is None:
        return ""
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        base = _expr_name(expr.value)
        return f"{base}.{expr.attr}" if base else expr.attr
    return ""


def _prompt_from_value(name: str, value: ast.expr, rel_path: str, line_number: int) -> ExtractedPrompt | None:
    text = _extract_string_value(value)
    if not text or len(text) <= 10:
        return None
    risk_flags = _check_prompt_risks(text)
    if _expr_contains_untrusted_prompt_input(value):
        risk_flags = [*risk_flags, "untrusted_input_interpolation"]
    return ExtractedPrompt(
        text=text[:2000],
        variable_name=name,
        file_path=rel_path,
        line_number=line_number,
        framework="generic",
        prompt_type=_classify_prompt_type(name),
        risk_flags=risk_flags,
    )


def _extract_python_prompts(tree: ast.Module, rel_path: str) -> list[ExtractedPrompt]:
    """Extract prompts from prompt-named assignments and prompt keyword arguments."""
    candidates: list[ExtractedPrompt | None] = []
    for node in ast.walk(tree):
        # Variable assignments: system_prompt = "You are..."
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id.lower() in _PROMPT_VAR_NAMES:
                    candidates.append(_prompt_from_value(target.id, node.value, rel_path, node.lineno))
        # Keyword arguments: Agent(system_prompt="You are...", instructions="...")
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg and kw.arg.lower() in _PROMPT_KWARG_NAMES:
                    candidates.append(_prompt_from_value(kw.arg, kw.value, rel_path, node.lineno))
    return [prompt for prompt in candidates if prompt is not None]


def _extract_params(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[dict]:
    """Extract function parameters with type annotations."""
    params = []
    for arg in func.args.args:
        if arg.arg == "self":
            continue
        param: dict = {"name": arg.arg, "type": "Any", "default": None}
        if arg.annotation:
            param["type"] = _annotation_to_str(arg.annotation)
        params.append(param)
    # Add defaults (aligned from the right)
    defaults = func.args.defaults
    if defaults:
        offset = len(params) - len(defaults)
        for i, d in enumerate(defaults):
            if isinstance(d, ast.Constant):
                params[offset + i]["default"] = repr(d.value)
    return params


def _get_return_annotation(func: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    """Extract return type annotation as string."""
    if func.returns:
        return _annotation_to_str(func.returns)
    return "None"


def _annotation_to_str(node: ast.expr) -> str:
    """Convert a type annotation AST node to a string."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Constant):
        return repr(node.value)
    if isinstance(node, ast.Attribute):
        return f"{_annotation_to_str(node.value)}.{node.attr}"
    if isinstance(node, ast.Subscript):
        return f"{_annotation_to_str(node.value)}[{_annotation_to_str(node.slice)}]"
    return "Any"
