"""Lexical scopes of a parsed Python module, built in one pass.

Every node maps to the qualified name of the function or class body it sits in
(``""`` for module level, ``"Builder.build"`` for a method body). Name lookups
follow Python's rule: the scope itself, then enclosing function scopes, then
the module; enclosing class bodies are skipped.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from typing import TypeVar

_V = TypeVar("_V")
_DEF_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef)


class ScopeIndex:
    """Enclosing scope per node, class scopes, and function definitions by qualified name."""

    def __init__(self, tree: ast.Module) -> None:
        self._scope_of: dict[int, str] = {}
        self.class_scopes: set[str] = set()
        self.functions: dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]] = {}
        self.function_qualnames: dict[str, list[str]] = {}
        stack: list[tuple[ast.AST, str]] = [(tree, "")]
        while stack:
            node, scope = stack.pop()
            for child in ast.iter_child_nodes(node):
                self._scope_of[id(child)] = scope
                stack.append((child, self._child_scope(child, scope)))

    @staticmethod
    def _qualify(scope: str, name: str) -> str:
        return f"{scope}.{name}" if scope else name

    def _child_scope(self, child: ast.AST, scope: str) -> str:
        if not isinstance(child, (*_DEF_TYPES, ast.ClassDef)):
            return scope
        qualname = self._qualify(scope, child.name)
        if isinstance(child, ast.ClassDef):
            self.class_scopes.add(qualname)
        else:
            self.functions.setdefault(qualname, []).append(child)
            self.function_qualnames.setdefault(child.name, []).append(qualname)
        return qualname

    def scope_of(self, node: ast.AST) -> str:
        """Qualified name of the function or class body that contains ``node``."""
        return self._scope_of.get(id(node), "")

    def chain(self, scope: str) -> Iterator[str]:
        """``scope``, then each enclosing non-class scope, ending at module level."""
        yield scope
        while scope:
            scope = scope.rpartition(".")[0]
            if scope not in self.class_scopes:
                yield scope

    def lookup(self, mapping: dict[tuple[str, str], _V], scope: str, name: str) -> _V | None:
        """The innermost ``(scope, name)`` entry visible from ``scope``."""
        for candidate in self.chain(scope):
            value = mapping.get((candidate, name))
            if value is not None:
                return value
        return None

    def enclosing_class(self, scope: str) -> str:
        """Qualified name of the nearest class whose body (or a method of it) contains ``scope``."""
        while scope:
            if scope in self.class_scopes:
                return scope
            scope = scope.rpartition(".")[0]
        return ""

    def resolve_function(self, ref: ast.AST | None, scope: str) -> str:
        """Qualified name of the function a node action names, or ``""`` when not statically known.

        ``fn`` resolves through the lexical chain, ``self.fn`` / ``cls.fn`` to the
        enclosing class, ``Cls.fn`` to a class of the module; any other
        ``obj.fn`` only when the module defines exactly one ``fn``.
        """
        if isinstance(ref, ast.Name):
            return next((q for q in (self._qualify(c, ref.id) for c in self.chain(scope)) if q in self.functions), "")
        if not isinstance(ref, ast.Attribute):
            return ""
        owner = ""
        if isinstance(ref.value, ast.Name) and ref.value.id in {"self", "cls"}:
            owner = self.enclosing_class(scope)
        elif isinstance(ref.value, ast.Name):
            owner = next((q for q in (self._qualify(c, ref.value.id) for c in self.chain(scope)) if q in self.class_scopes), "")
        if owner and f"{owner}.{ref.attr}" in self.functions:
            return f"{owner}.{ref.attr}"
        candidates = self.function_qualnames.get(ref.attr, [])
        return candidates[0] if len(set(candidates)) == 1 else ""
