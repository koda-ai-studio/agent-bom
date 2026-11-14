"""Resolve an eval suite's declared target to the framework agents of the same project.

Only references the files determine are resolved: a promptfoo ``file://`` entry
file, or a Python name the eval imports from a project module that defines
framework agents. A reference that does not resolve stays on the suite with the
reason, and the suite is reported unlinked rather than attached to a guess.
"""

from __future__ import annotations

import ast
from pathlib import Path, PurePosixPath
from typing import Any

from agent_bom.ast.source_reader import parse_python_source

_MAX_MODULE_BYTES = 512 * 1024


class AgentIndex:
    """Framework agents of one project scope, addressable by file and name."""

    def __init__(self, framework_agents: list[dict[str, Any]], scope: str) -> None:
        self.by_file: dict[str, list[dict[str, Any]]] = {}
        for agent in framework_agents:
            if not isinstance(agent, dict) or not agent.get("stable_id"):
                continue
            if str(agent.get("scope") or "") != scope:
                continue
            self.by_file.setdefault(_norm(str(agent.get("file_path") or "")), []).append(agent)
        self._bindings: dict[str, dict[str, set[str]]] = {}

    def roots_in_file(self, rel_path: str) -> list[str]:
        agents = self.by_file.get(_norm(rel_path), [])
        ids = {str(agent["stable_id"]) for agent in agents}
        return sorted(str(agent["stable_id"]) for agent in agents if str(agent.get("parent_id") or "") not in ids)

    def symbol_in_file(self, root: Path, rel_path: str, symbol: str) -> list[str]:
        """Agents a module-level name of ``rel_path`` denotes: the agent itself or a value built from it."""
        agents = self.by_file.get(_norm(rel_path), [])
        named = sorted(str(agent["stable_id"]) for agent in agents if agent.get("name") == symbol)
        if named:
            return named
        roots = self._module_bindings(root, rel_path).get(symbol, set())
        return sorted(str(agent["stable_id"]) for agent in agents if agent.get("name") in roots)

    def _module_bindings(self, root: Path, rel_path: str) -> dict[str, set[str]]:
        key = _norm(rel_path)
        if key not in self._bindings:
            self._bindings[key] = _assigned_roots(root / rel_path)
        return self._bindings[key]


def _norm(path: str) -> str:
    return str(PurePosixPath(path.replace("\\", "/")))


def _assigned_roots(path: Path) -> dict[str, set[str]]:
    """Module-level ``name = expr`` bindings mapped to the names ``expr`` is built from."""
    try:
        if path.stat().st_size > _MAX_MODULE_BYTES:
            return {}
        tree = parse_python_source(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))
    except (OSError, SyntaxError, ValueError):
        return {}
    bindings: dict[str, set[str]] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            names = {target.id for target in node.targets if isinstance(target, ast.Name)}
            roots = {child.id for child in ast.walk(node.value) if isinstance(child, ast.Name)}
            for name in names:
                bindings.setdefault(name, set()).update(roots)
    return bindings


def resolve_module_file(root: Path, eval_file: Path, module: str, level: int = 0) -> str | None:
    """The project-relative file a Python import names, when it is a module of this project."""
    parts = [part for part in module.split(".") if part]
    bases = [eval_file.parent] if level else [root, eval_file.parent]
    if level > 1:
        bases = [eval_file.parents[level - 1]] if len(eval_file.parents) >= level else []
    for base in bases:
        for candidate in (base.joinpath(*parts).with_suffix(".py") if parts else None, base.joinpath(*parts, "__init__.py")):
            if candidate is None or not candidate.is_file():
                continue
            try:
                return candidate.resolve().relative_to(root.resolve()).as_posix()
            except ValueError:
                return None
    return None


def resolve_entry_file(root: Path, config_dir: Path, ref: str) -> str | None:
    """A promptfoo ``file://`` provider path (with optional ``:function``) as a project-relative file."""
    head, sep, tail = ref.rpartition(":")
    path_text = head if sep and head and tail.isidentifier() else ref
    for base in (config_dir, root):
        candidate = (base / path_text).resolve()
        try:
            rel = candidate.relative_to(root.resolve()).as_posix()
        except ValueError:
            continue
        if candidate.is_file():
            return rel
    return None
