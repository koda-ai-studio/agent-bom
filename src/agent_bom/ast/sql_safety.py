"""Decide whether a string-built SQL query can carry untrusted text.

The SQL-sink rule fires when ``execute()`` receives a dynamically built string
(or a local name built that way) unless every interpolated piece is a value
that cannot carry caller input (see :mod:`agent_bom.ast.safe_values`): literal
text, bind-placeholder markers, module UPPER_CASE constants, numeric coercions,
psycopg ``sql`` composables, validator results, and local names or lists whose
every binding is such a value.

A reviewer marker (:mod:`agent_bom.ast.flow_suppression`) on the call or on a
line that built the query suppresses the finding, and the verdict carries the
marker text so the finding is recorded as suppressed rather than dropped.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from agent_bom.ast.flow_suppression import FlowSuppressions
from agent_bom.ast.safe_value_facts import ModuleValueFacts
from agent_bom.ast.safe_values import SafeValueScope

SQL_CATEGORY = "sql_string_construction"


def expr_uses_dynamic_string(expr: ast.AST | None) -> bool:
    """f-string, ``+``/``%`` string building, or ``str.format``."""
    if expr is None:
        return False
    if isinstance(expr, ast.JoinedStr):
        return True
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
        return True
    return isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "format"


@dataclass(frozen=True)
class ModuleSqlFacts:
    """Per-file inputs shared by every function's SQL check."""

    values: ModuleValueFacts
    suppressions: FlowSuppressions

    @classmethod
    def from_source(cls, tree: ast.Module, source: str) -> ModuleSqlFacts:
        return cls(values=ModuleValueFacts.from_tree(tree), suppressions=FlowSuppressions.from_source(source))

    def for_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> FunctionSqlScope:
        return FunctionSqlScope(self, node)


class FunctionSqlScope:
    """Per-function SQL verdicts; the value scopes are built on first use."""

    def __init__(self, module: ModuleSqlFacts, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.module = module
        self._node = node
        self._strict: SafeValueScope | None = None
        self._reviewed: SafeValueScope | None = None

    @property
    def strict(self) -> SafeValueScope:
        """Ignores reviewer markers."""
        if self._strict is None:
            self._strict = SafeValueScope(self.module.values, self._node, self.module.values.class_of.get(id(self._node)))
        return self._strict

    @property
    def reviewed(self) -> SafeValueScope:
        """Treats bindings on marker lines as reviewed-safe."""
        if self._reviewed is None:
            lines = self.module.suppressions.lines_for(SQL_CATEGORY)
            self._reviewed = SafeValueScope(self.module.values, self._node, self.module.values.class_of.get(id(self._node)), lines)
        return self._reviewed

    def verdict(self, call: ast.Call) -> str | None:
        """``None`` when not reported, ``""`` when active, else the suppressing marker text."""
        query = call.args[0] if call.args else None
        if query is None or not _query_unsafe(self.strict, query, call.lineno):
            return None
        if (marker := self.module.suppressions.marker_for(SQL_CATEGORY, call)) is not None:
            return marker
        if _query_unsafe(self.reviewed, query, call.lineno):
            return ""
        return self._upstream_marker(query) or "nosec (reviewed upstream assignment)"

    def query_is_unsafe(self, call: ast.Call) -> bool:
        """True when the first ``execute`` argument may carry untrusted text and no marker waives it."""
        return self.verdict(call) == ""

    def _upstream_marker(self, query: ast.AST) -> str | None:
        suppressions = self.module.suppressions
        referenced = {n.id for n in ast.walk(query) if isinstance(n, ast.Name)}
        lines = sorted(
            line
            for name in referenced
            for line in self.strict.bindings.store_lines.get(name, [])
            if suppressions.marker_at(SQL_CATEGORY, line) is not None
        )
        lines = lines or sorted(line for line in suppressions.lines_for(SQL_CATEGORY) if _within(self._node, line))
        return suppressions.marker_at(SQL_CATEGORY, lines[0]) if lines else None


def _within(node: ast.AST, line: int) -> bool:
    return getattr(node, "lineno", 0) <= line <= (getattr(node, "end_lineno", None) or 0)


def _query_unsafe(scope: SafeValueScope, query: ast.AST, line: int) -> bool:
    if expr_uses_dynamic_string(query):
        return not scope.is_safe(query, line)
    if not isinstance(query, ast.Name) or scope.is_safe(query, line):
        return False
    bindings = scope.bindings
    built = any(expr_uses_dynamic_string(value) for value, _, _ in bindings.values.get(query.id, []))
    return built or bool(bindings.augments.get(query.id))
