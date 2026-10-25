"""Enclosing class/function scope of every call in a Python module."""

from __future__ import annotations

import ast


def call_scopes(tree: ast.Module) -> dict[int, str]:
    """Map each call node (by ``id``) to its enclosing class/function qualname; "" at module level."""
    scopes: dict[int, str] = {}

    def visit(node: ast.AST, scope: str) -> None:
        for child in ast.iter_child_nodes(node):
            child_scope = scope
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                child_scope = f"{scope}.{child.name}" if scope else child.name
            elif isinstance(child, ast.Call):
                scopes[id(child)] = scope
            visit(child, child_scope)

    visit(tree, "")
    return scopes
