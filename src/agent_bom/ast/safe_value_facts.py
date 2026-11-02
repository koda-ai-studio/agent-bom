"""Module-level facts the safe-value analysis needs: constants, validators, validated attributes.

A *validator* is either

* a function in the same module that returns its first argument unchanged on
  every path and raises from inside an ``if`` (the ``_validate_identifier`` /
  ``_warehouse_ident`` shape), or
* any call whose final name segment contains ``validate`` (``validate_url``,
  ``validate_sql_identifier``) — the naming contract the repository's own
  guards follow.

A class attribute is *validated* when every ``self.<attr> = ...`` in the class
assigns a validator call result or a literal string.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

_CONSTANT_NAME_RE = re.compile(r"^_*[A-Z][A-Z0-9_]*$")


def call_tail(call: ast.Call) -> str:
    """Last dotted segment of the called name (``validate_url`` for ``security.validate_url``)."""
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _module_constants(tree: ast.Module) -> frozenset[str]:
    names: set[str] = set()
    for stmt in tree.body:
        targets: list[ast.AST] = []
        if isinstance(stmt, ast.Assign):
            targets = list(stmt.targets)
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            targets = [stmt.target]
        elif isinstance(stmt, ast.ImportFrom):
            names.update(a.asname or a.name for a in stmt.names if _CONSTANT_NAME_RE.match(a.asname or a.name))
        names.update(t.id for t in targets if isinstance(t, ast.Name) and _CONSTANT_NAME_RE.match(t.id))
    return frozenset(names)


def _own_nodes(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.AST]:
    nodes: list[ast.AST] = []
    stack: list[ast.AST] = list(func.body)
    while stack:
        node = stack.pop()
        nodes.append(node)
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            stack.extend(ast.iter_child_nodes(node))
    return nodes


def is_structural_validator(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Returns its first parameter unchanged on every path and raises under an ``if``."""
    params = [*func.args.posonlyargs, *func.args.args]
    if not params:
        return False
    first = params[0].arg
    nodes = _own_nodes(func)
    returns = [n for n in nodes if isinstance(n, ast.Return)]
    if not returns or not all(isinstance(r.value, ast.Name) and r.value.id == first for r in returns):
        return False
    if any(isinstance(n, ast.Name) and n.id == first and isinstance(n.ctx, ast.Store) for n in nodes):
        return False
    return any(isinstance(n, ast.If) and any(isinstance(inner, ast.Raise) for inner in ast.walk(n)) for n in nodes)


@dataclass(frozen=True)
class ModuleValueFacts:
    constants: frozenset[str] = frozenset()
    validators: frozenset[str] = frozenset()
    validated_attrs: dict[str, frozenset[str]] = field(default_factory=dict)
    class_of: dict[int, str] = field(default_factory=dict)

    @classmethod
    def from_tree(cls, tree: ast.Module) -> ModuleValueFacts:
        validators = frozenset(
            stmt.name for stmt in tree.body if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) and is_structural_validator(stmt)
        )
        base = cls(constants=_module_constants(tree), validators=validators)
        attrs: dict[str, frozenset[str]] = {}
        class_of: dict[int, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                attrs[node.name] = _validated_attrs(node, base)
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        class_of[id(item)] = node.name
        return cls(constants=base.constants, validators=validators, validated_attrs=attrs, class_of=class_of)


def is_validator_call(call: ast.Call, facts: ModuleValueFacts) -> bool:
    tail = call_tail(call)
    if isinstance(call.func, ast.Name) and tail in facts.validators:
        return True
    return "validate" in tail.lower()


def _validated_attrs(cls_node: ast.ClassDef, facts: ModuleValueFacts) -> frozenset[str]:
    verdicts: dict[str, bool] = {}
    for node in ast.walk(cls_node):
        if isinstance(node, ast.AugAssign) and _self_attr(node.target):
            verdicts[_self_attr(node.target)] = False
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(node, ast.AnnAssign) else []
        value = getattr(node, "value", None)
        for target in targets:
            attr = _self_attr(target)
            if not attr:
                if isinstance(target, (ast.Tuple, ast.List)):
                    for elt in target.elts:
                        if _self_attr(elt):
                            verdicts[_self_attr(elt)] = False
                continue
            ok = (isinstance(value, ast.Call) and is_validator_call(value, facts)) or (
                isinstance(value, ast.Constant) and isinstance(value.value, str)
            )
            verdicts[attr] = verdicts.get(attr, True) and ok
    return frozenset(attr for attr, ok in verdicts.items() if ok)


def _self_attr(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "self":
        return node.attr
    return ""
