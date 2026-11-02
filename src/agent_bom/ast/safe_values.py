"""Which string values inside one Python function cannot carry caller input.

A value is safe when every piece of text in it comes from a literal, a
module-level UPPER_CASE constant the function does not rebind, a numeric
coercion, a psycopg ``sql`` composable, an explicit validator's result, or a
local name/list whose every binding is itself safe. Validation is honoured
only after the validating call and only while the name is not rebound.

The analysis is intra-procedural and syntactic. It never proves a value
dangerous; the sink rules use it to stop reporting values that cannot carry
attacker text.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from dataclasses import dataclass, field

from agent_bom.ast.safe_value_facts import ModuleValueFacts, call_tail, is_validator_call

_NUMERIC_CALLS = frozenset({"int", "float", "len", "bool", "round", "abs"})
_ITER_WRAPPERS = frozenset({"sorted", "list", "tuple", "set", "frozenset", "reversed"})
_MAPPING_VIEWS = frozenset({"items", "keys", "values"})
_STR_METHODS = frozenset(
    {"lower", "upper", "strip", "lstrip", "rstrip", "casefold", "title", "replace", "removeprefix", "removesuffix", "zfill"}
)
_LIST_MUTATORS = frozenset({"append", "extend", "insert"})
_LIST_READERS = frozenset({"len", "bool", "sorted", "tuple", "list", "set", "any", "all"})
_PSYCOPG_COMPOSABLES = frozenset({"SQL", "Identifier", "Literal", "Placeholder", "Composed"})


def _scope_nodes(func: ast.AST) -> Iterator[ast.AST]:
    """Nodes of ``func`` excluding nested function, lambda and class bodies."""
    stack = list(ast.iter_child_nodes(func))
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            stack.extend(ast.iter_child_nodes(node))


def _target_names(target: ast.AST) -> list[str]:
    return [node.id for node in ast.walk(target) if isinstance(node, ast.Name)]


@dataclass
class _Bindings:
    """Every way the function binds each local name."""

    values: dict[str, list[tuple[ast.AST, int, int]]] = field(default_factory=dict)
    augments: dict[str, list[tuple[ast.AST, int, int]]] = field(default_factory=dict)
    iterations: dict[str, list[ast.AST]] = field(default_factory=dict)
    opaque: set[str] = field(default_factory=set)
    store_lines: dict[str, list[int]] = field(default_factory=dict)

    def add_value(self, target: ast.AST, value: ast.AST, stmt: ast.AST) -> None:
        if isinstance(target, ast.Name):
            start = getattr(stmt, "lineno", 0)
            self.values.setdefault(target.id, []).append((value, start, getattr(stmt, "end_lineno", None) or start))
        elif isinstance(target, (ast.Tuple, ast.List)) and isinstance(value, ast.expr):
            # ``a, b = x, "s"`` binds like one iteration over the single row ``(x, "s")``.
            self.add_iteration(target, ast.Tuple(elts=[value], ctx=ast.Load()))

    def add_iteration(self, target: ast.AST, iterable: ast.AST) -> None:
        columns = _unpacked_columns(target, iterable)
        if columns is not None:
            for name, column in columns:
                self.iterations.setdefault(name, []).append(column)
            return
        for name in _target_names(target):
            self.iterations.setdefault(name, []).append(iterable)


def _unpacked_columns(target: ast.AST, iterable: ast.AST) -> list[tuple[str, ast.AST]] | None:
    """``for a, b in ((x, "s"), (y, "t"))``: bind each name to its own column of the literal rows."""
    if not isinstance(target, ast.Tuple) or not isinstance(iterable, (ast.List, ast.Tuple)) or not iterable.elts:
        return None
    width = len(target.elts)
    rows = iterable.elts
    if not all(isinstance(row, ast.Tuple) and len(row.elts) == width for row in rows):
        return None
    columns: list[tuple[str, ast.AST]] = []
    for index, element in enumerate(target.elts):
        column = ast.Tuple(elts=[row.elts[index] for row in rows if isinstance(row, ast.Tuple)], ctx=ast.Load())
        if isinstance(element, ast.Name):
            columns.append((element.id, column))
        else:
            columns.extend((name, column) for name in _target_names(element))
    return columns


def _collect_bindings(func: ast.FunctionDef | ast.AsyncFunctionDef) -> _Bindings:
    bindings = _Bindings()
    explained: set[int] = set()
    comprehension_targets: set[int] = set()
    for node in _scope_nodes(func):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                bindings.add_value(target, node.value, node)
                explained.update(id(n) for n in ast.walk(target))
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            bindings.add_value(node.target, node.value, node)
            explained.update(id(n) for n in ast.walk(node.target))
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
            if isinstance(node.op, ast.Add):
                end = getattr(node, "end_lineno", None) or node.lineno
                bindings.augments.setdefault(node.target.id, []).append((node.value, node.lineno, end))
            else:
                bindings.opaque.add(node.target.id)
            explained.add(id(node.target))
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            bindings.add_iteration(node.target, node.iter)
            explained.update(id(n) for n in ast.walk(node.target))
        elif isinstance(node, ast.comprehension):
            # Comprehension targets do not leak into the function scope; the
            # comprehension's own element check binds them.
            comprehension_targets.update(id(n) for n in ast.walk(node.target))
        elif isinstance(node, ast.NamedExpr):
            bindings.add_value(node.target, node.value, node)
            explained.add(id(node.target))
    for node in _scope_nodes(func):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)) and id(node) not in comprehension_targets:
            bindings.store_lines.setdefault(node.id, []).append(node.lineno)
            if id(node) not in explained:
                bindings.opaque.add(node.id)
    return bindings


class SafeValueScope:
    """Per-function safe-value oracle; built lazily by the sink rules."""

    def __init__(
        self,
        facts: ModuleValueFacts,
        func: ast.FunctionDef | ast.AsyncFunctionDef,
        class_name: str | None,
        reviewed_lines: frozenset[int] = frozenset(),
    ) -> None:
        self._facts = facts
        self._func = func
        self._attrs = facts.validated_attrs.get(class_name or "", frozenset())
        self._reviewed = reviewed_lines
        args = func.args
        self.params = frozenset(a.arg for a in [*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg] if a is not None)
        self.bindings = _collect_bindings(func)
        self._parents = {id(child): parent for parent in _scope_nodes(func) for child in ast.iter_child_nodes(parent)}
        self._validations = self._collect_validations()
        self.safe_names: frozenset[str] = frozenset()
        self.safe_lists: frozenset[str] = frozenset()
        self._solve()

    # ── validation ──────────────────────────────────────────────────────────

    def _collect_validations(self) -> dict[str, list[int]]:
        found: dict[str, list[int]] = {}
        for node in _scope_nodes(self._func):
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) and node.value.args:
                if is_validator_call(node.value, self._facts):
                    key = _validation_key(node.value.args[0])
                    if key:
                        found.setdefault(key, []).append(node.lineno)
        return found

    def validated(self, expr: ast.AST, line: int) -> bool:
        key = _validation_key(expr)
        if not key or key not in self._validations:
            return False
        earlier = [v for v in self._validations[key] if v < line]
        if not earlier:
            return False
        last = max(earlier)
        if key.startswith("self."):
            return not self._attr_assigned(key[5:])
        return not any(last < store <= line for store in self.bindings.store_lines.get(key, []))

    def _attr_assigned(self, attr: str) -> bool:
        return any(
            isinstance(n, ast.Attribute) and isinstance(n.ctx, ast.Store) and n.attr == attr and _is_self(n.value)
            for n in _scope_nodes(self._func)
        )

    # ── fixpoint over local names ───────────────────────────────────────────

    def _solve(self) -> None:
        b = self.bindings
        candidates = (set(b.values) | set(b.augments) | set(b.iterations)) - set(self.params) - b.opaque
        mutable = {n for n in candidates if self._binds_mutable(n)}
        lists = {n for n in mutable if self._list_shaped(n)}
        names = (set(candidates) - mutable) | lists
        changed = True
        while changed:
            self.safe_names, self.safe_lists = frozenset(names), frozenset(lists)
            changed = False
            for name in list(names):
                if not self._name_bindings_safe(name):
                    names.discard(name)
                    changed = True
            for name in list(lists):
                if name not in names or not self._list_uses_safe(name):
                    lists.discard(name)
                    names.discard(name)
                    changed = True
        self.safe_names, self.safe_lists = frozenset(names), frozenset(lists)

    def _list_shaped(self, name: str) -> bool:
        values = self.bindings.values.get(name, [])
        return bool(values) and all(isinstance(value, (ast.List, ast.Tuple, ast.ListComp)) for value, _, _ in values)

    def _binds_mutable(self, name: str) -> bool:
        mutable = (ast.List, ast.ListComp, ast.Set, ast.SetComp, ast.Dict, ast.DictComp)
        return any(isinstance(value, mutable) for value, _, _ in self.bindings.values.get(name, []))

    def _name_bindings_safe(self, name: str) -> bool:
        b = self.bindings
        for value, line, end in [*b.values.get(name, []), *b.augments.get(name, [])]:
            if any(reviewed in self._reviewed for reviewed in range(line, end + 1)):
                continue
            if not (self.is_safe(value, line) or self.is_safe_iter(value, line)):
                return False
        return all(self.is_safe_iter(iterable, 0) for iterable in b.iterations.get(name, []))

    def _list_uses_safe(self, name: str) -> bool:
        for node in _scope_nodes(self._func):
            if not (isinstance(node, ast.Name) and node.id == name and isinstance(node.ctx, ast.Load)):
                continue
            if not self._list_use_safe(node):
                return False
        return True

    def _list_use_safe(self, node: ast.Name) -> bool:
        parent = self._parents.get(id(node))
        if isinstance(parent, ast.Attribute) and parent.value is node:
            call = self._parents.get(id(parent))
            if not isinstance(call, ast.Call) or call.func is not parent:
                return False
            if parent.attr in _LIST_MUTATORS:
                return all(self.is_safe(a, 0) or self.is_safe_iter(a, 0) for a in call.args) and not call.keywords
            return parent.attr in {"copy", "count", "index"}
        if isinstance(parent, ast.Call):
            if parent.func is node:
                return False
            tail = call_tail(parent)
            is_join = isinstance(parent.func, ast.Attribute) and parent.func.attr == "join"
            return is_join or tail in _LIST_READERS
        if isinstance(parent, ast.Subscript):
            return parent.value is node and isinstance(parent.ctx, ast.Load)
        return isinstance(parent, (ast.If, ast.IfExp, ast.BoolOp, ast.UnaryOp, ast.For, ast.comprehension, ast.Compare))

    # ── expressions ─────────────────────────────────────────────────────────

    def _name_safe(self, name: str, line: int, node: ast.AST) -> bool:
        if name in self.safe_names or name in self.safe_lists:
            return True
        if name in self._facts.constants and name not in self.params and name not in self.bindings.store_lines:
            return True
        return self.validated(node, line)

    def is_safe(self, expr: ast.AST | None, line: int) -> bool:
        """True when ``expr`` evaluates to text no caller can influence."""
        if expr is None:
            return False
        if isinstance(expr, ast.Constant):
            return True
        if isinstance(expr, ast.Name):
            return self._name_safe(expr.id, line, expr)
        if isinstance(expr, ast.Attribute):
            return (_is_self(expr.value) and expr.attr in self._attrs) or self.validated(expr, line)
        if isinstance(expr, ast.JoinedStr):
            return all(self.is_safe(part.value, line) for part in expr.values if isinstance(part, ast.FormattedValue))
        if isinstance(expr, ast.BinOp):
            return self._binop_safe(expr, line)
        if isinstance(expr, ast.IfExp):
            return self.is_safe(expr.body, line) and self.is_safe(expr.orelse, line)
        if isinstance(expr, ast.Subscript):
            return self.is_safe(expr.value, line) or self.is_safe_iter(expr.value, line)
        if isinstance(expr, ast.Call):
            return self._call_safe(expr, line)
        return False

    def _binop_safe(self, expr: ast.BinOp, line: int) -> bool:
        if isinstance(expr.op, ast.Add):
            return self.is_safe(expr.left, line) and self.is_safe(expr.right, line)
        if isinstance(expr.op, ast.Mod):
            right = expr.right.elts if isinstance(expr.right, ast.Tuple) else [expr.right]
            return self.is_safe(expr.left, line) and all(self.is_safe(item, line) for item in right)
        if isinstance(expr.op, ast.Mult):
            return any(_is_text_literal(side) and self.is_safe(side, line) for side in (expr.left, expr.right))
        return False

    def _call_safe(self, call: ast.Call, line: int) -> bool:
        if _is_psycopg_composable(call):
            return True
        if is_validator_call(call, self._facts):
            return True
        tail = call_tail(call)
        if isinstance(call.func, ast.Name) and tail in _NUMERIC_CALLS:
            return True
        if isinstance(call.func, ast.Name) and tail == "str":
            return len(call.args) == 1 and self.is_safe(call.args[0], line)
        if not isinstance(call.func, ast.Attribute):
            return False
        receiver, method = call.func.value, call.func.attr
        args_safe = all(self.is_safe(a.value if isinstance(a, ast.Starred) else a, line) for a in call.args) and all(
            self.is_safe(k.value, line) for k in call.keywords
        )
        if method == "format":
            return self.is_safe(receiver, line) and args_safe
        if method == "join":
            return self.is_safe(receiver, line) and len(call.args) == 1 and self.is_safe_iter(call.args[0], line)
        return method in _STR_METHODS and self.is_safe(receiver, line) and args_safe

    def is_safe_iter(self, expr: ast.AST | None, line: int) -> bool:
        """True when iterating ``expr`` yields only safe values (nested tuples allowed)."""
        if expr is None:
            return False
        if isinstance(expr, (ast.Constant, ast.JoinedStr, ast.BinOp)) and self.is_safe(expr, line):
            return True  # iterating safe text yields safe characters
        if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            return all(self.is_safe(e, line) or self.is_safe_iter(e, line) for e in expr.elts)
        if isinstance(expr, ast.Dict):
            return all(k is not None and self.is_safe(k, line) for k in expr.keys)
        if isinstance(expr, ast.Name):
            return self._name_safe(expr.id, line, expr)
        if isinstance(expr, (ast.GeneratorExp, ast.ListComp, ast.SetComp)):
            return self.is_safe(expr.elt, line) or self._comprehension_elt_safe(expr, line)
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            return self.is_safe_iter(expr.left, line) and self.is_safe_iter(expr.right, line)
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Mult):
            return any(isinstance(side, (ast.List, ast.Tuple)) and self.is_safe_iter(side, line) for side in (expr.left, expr.right))
        if isinstance(expr, ast.Call):
            return self._iter_call_safe(expr, line)
        return False

    def _iter_call_safe(self, call: ast.Call, line: int) -> bool:
        if isinstance(call.func, ast.Name) and call.func.id in _ITER_WRAPPERS and len(call.args) == 1:
            return self.is_safe_iter(call.args[0], line)
        if isinstance(call.func, ast.Attribute) and call.func.attr in _MAPPING_VIEWS and not call.args:
            return self.is_safe_iter(call.func.value, line)
        return False

    def _comprehension_elt_safe(self, comp: ast.GeneratorExp | ast.ListComp | ast.SetComp, line: int) -> bool:
        """Comprehension targets drawn from safe iterables are safe inside the element."""
        if not all(self.is_safe_iter(gen.iter, line) for gen in comp.generators):
            return False
        extra = {name for gen in comp.generators for name in _target_names(gen.target)}
        saved = self.safe_names
        self.safe_names = saved | extra
        try:
            return self.is_safe(comp.elt, line)
        finally:
            self.safe_names = saved


def _is_self(expr: ast.AST) -> bool:
    return isinstance(expr, ast.Name) and expr.id == "self"


def _validation_key(expr: ast.AST) -> str:
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute) and _is_self(expr.value):
        return f"self.{expr.attr}"
    return ""


def _is_text_literal(expr: ast.AST) -> bool:
    return (isinstance(expr, ast.Constant) and isinstance(expr.value, str)) or isinstance(expr, (ast.List, ast.Tuple))


def _is_psycopg_composable(call: ast.Call) -> bool:
    """``sql.SQL("...")``, ``sql.Identifier(x)``, and ``.format``/``.join`` on a literal ``sql.SQL``."""
    func = call.func
    if isinstance(func, ast.Attribute) and func.attr in {"format", "join"} and isinstance(func.value, ast.Call):
        inner = func.value
        return _composable_name(inner) == "SQL" and _literal_sql_template(inner)
    name = _composable_name(call)
    if name == "SQL":
        return _literal_sql_template(call)
    return name in _PSYCOPG_COMPOSABLES


def _composable_name(call: ast.Call) -> str:
    func = call.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id == "sql":
        return func.attr
    return ""


def _literal_sql_template(call: ast.Call) -> bool:
    return len(call.args) == 1 and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str)
