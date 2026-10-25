"""Declared dependency names and versions from a ``pyproject.toml``.

Reads PEP 621 ``[project] dependencies`` and ``optional-dependencies``, PEP 735
``[dependency-groups]``, and Poetry ``dependencies`` / ``dev-dependencies`` /
``group.<name>.dependencies``. Requirement strings may carry extras
(``crewai[tools]>=0.80``) and markers. The version is the first concrete
version in the specifier, or ``"unknown"`` when none is declared.
"""

from __future__ import annotations

import re
import tomllib
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from agent_bom.parsers.file_limits import read_text_limited

_REQUIREMENT_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$")
_VERSION_RE = re.compile(r"[=~!<>^]*\s*v?([0-9][^\s,;'\"]*)")


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _version_from_spec(spec: str) -> str:
    spec = spec.split(";", 1)[0].strip()
    match = _VERSION_RE.search(spec)
    return match.group(1) if match else "unknown"


def _from_requirement_strings(values: Iterable[Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for value in values:
        if not isinstance(value, str):
            continue
        match = _REQUIREMENT_RE.match(value)
        if match:
            out[normalize_name(match.group(1))] = _version_from_spec(match.group(2))
    return out


def _from_poetry_table(table: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    if not isinstance(table, dict):
        return out
    for name, spec in table.items():
        if not isinstance(name, str) or name.lower() == "python":
            continue
        if isinstance(spec, dict):
            spec = spec.get("version", "")
        out[normalize_name(name)] = _version_from_spec(spec) if isinstance(spec, str) else "unknown"
    return out


def _table(data: Any, *keys: str) -> Any:
    for key in keys:
        if not isinstance(data, dict):
            return None
        data = data.get(key)
    return data


def declared_dependencies(data: dict[str, Any]) -> dict[str, str]:
    """``{normalized_name: version}`` for every dependency a parsed pyproject declares."""
    out: dict[str, str] = {}
    project = _table(data, "project") or {}
    out.update(_from_requirement_strings(_table(project, "dependencies") or []))
    for group in (_table(project, "optional-dependencies") or {}).values():
        if isinstance(group, list):
            out.update(_from_requirement_strings(group))
    for group in (_table(data, "dependency-groups") or {}).values():
        if isinstance(group, list):
            out.update(_from_requirement_strings(group))
    poetry = _table(data, "tool", "poetry") or {}
    out.update(_from_poetry_table(_table(poetry, "dependencies")))
    out.update(_from_poetry_table(_table(poetry, "dev-dependencies")))
    for group in (_table(poetry, "group") or {}).values():
        out.update(_from_poetry_table(_table(group, "dependencies")))
    return out


def parse_pyproject_dependencies(path: Path) -> dict[str, str]:
    """Declared dependencies of the pyproject at *path*; empty when it does not parse."""
    try:
        data = tomllib.loads(read_text_limited(path, errors="replace"))
    except (OSError, ValueError):
        return {}
    return declared_dependencies(data)
