"""Bounded syntax-only Python input shared by repository evidence adapters."""

from __future__ import annotations

import ast
import hashlib
import re
from collections.abc import Iterator
from typing import Any

from agent_bom.parsers.repository.artifacts import RepositoryReader


def literal(value: Any) -> str | None:
    value = value.value if isinstance(value, ast.Constant) else value
    return value if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_./:@ -]{0,255}", value) else None


def symbol(node: ast.AST, aliases: dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, "")
    if isinstance(node, ast.Attribute):
        base = symbol(node.value, aliases)
        return f"{base}.{node.attr}" if base else ""
    return ""


def import_aliases(tree: ast.Module) -> dict[str, str]:
    result: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                result[alias.asname or alias.name.split(".")[0]] = alias.name if alias.asname else alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
            for alias in node.names:
                if alias.name != "*":
                    result[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return result


def source_trees(reader: RepositoryReader, paths: list[str]) -> Iterator[tuple[str, str, ast.Module]]:
    for path in paths:
        text = reader.read(path, max_bytes=256 * 1024)
        if text is None:
            continue
        try:
            tree = ast.parse(text, filename=path)
            if sum(1 for _ in ast.walk(tree)) > 20_000:
                reader.note(path, "syntax_node_limit")
                continue
        except (SyntaxError, ValueError, RecursionError):
            reader.note(path, "source_syntax_unavailable")
            continue
        yield path, hashlib.sha256(text.encode()).hexdigest(), tree
