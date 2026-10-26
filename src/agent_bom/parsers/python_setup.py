"""Static ``setup.cfg`` / ``setup.py`` dependency declarations.

``setup.py`` is read with :mod:`ast` and never executed: only literal lists
(directly, or through a module-level name bound to a literal) are trusted.
Anything computed records a manifest coverage gap instead of a silent empty
result.
"""

from __future__ import annotations

import ast
import configparser
import logging
import tomllib
from pathlib import Path

from agent_bom.coverage import record_manifest_parse_warning
from agent_bom.models import Package
from agent_bom.parsers.file_limits import read_text_limited
from agent_bom.parsers.python_requirements import clean_requirement_line, requirement_line_package

logger = logging.getLogger(__name__)

_SETUP_CALLS = frozenset({"setup", "setuptools.setup", "distutils.core.setup"})


def _packages_from_strings(values: list[str]) -> tuple[list[Package], bool]:
    packages: list[Package] = []
    malformed = False
    for value in values:
        line = clean_requirement_line(value.strip())
        if not line or line.startswith("#"):
            continue
        parsed = requirement_line_package(line, is_direct=True)
        if isinstance(parsed, Package):
            packages.append(parsed)
        elif parsed is None:
            malformed = True
    return packages, malformed


def _gap(path: Path, detail: str) -> None:
    record_manifest_parse_warning(ecosystem="pypi", path=str(path), detail=detail)


def parse_setup_cfg(path: Path) -> tuple[list[Package], bool]:
    """Return ``(packages, declares_install_requires)`` for a ``setup.cfg``."""
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(read_text_limited(path, errors="replace"))
    except (OSError, ValueError, configparser.Error) as exc:
        logger.debug("Failed to parse setup.cfg at %s: %s", path, exc)
        _gap(path, "setup.cfg could not be read or parsed; Python dependencies were not scanned")
        return [], False
    values: list[str] = []
    declared = parser.has_option("options", "install_requires")
    raw = parser.get("options", "install_requires", fallback="")
    if raw.strip().startswith("file:"):
        _gap(path, "setup.cfg reads install_requires from a file: directive; Python dependency coverage is partial")
        raw = ""
    values.extend(raw.splitlines())
    if parser.has_section("options.extras_require"):
        for _, extra in parser.items("options.extras_require"):
            values.extend(extra.splitlines())
    packages, malformed = _packages_from_strings(values)
    if malformed:
        _gap(path, "setup.cfg contains malformed requirement entries; Python dependency coverage is partial")
    return packages, declared


def _call_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_call_name(node.value)}.{node.attr}"
    return ""


def _literal_bindings(tree: ast.Module) -> dict[str, ast.expr]:
    bindings: dict[str, ast.expr] = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            bindings[stmt.targets[0].id] = stmt.value
    return bindings


def _string_list(node: ast.expr | None, bindings: dict[str, ast.expr]) -> list[str] | None:
    if isinstance(node, ast.Name):
        node = bindings.get(node.id)
    if not isinstance(node, (ast.List, ast.Tuple)):
        return None
    values = [element.value for element in node.elts if isinstance(element, ast.Constant) and isinstance(element.value, str)]
    return values if len(values) == len(node.elts) else None


def _extras_lists(node: ast.expr | None, bindings: dict[str, ast.expr]) -> list[str] | None:
    if isinstance(node, ast.Name):
        node = bindings.get(node.id)
    if not isinstance(node, ast.Dict):
        return None
    values: list[str] = []
    for value in node.values:
        items = _string_list(value, bindings)
        if items is None:
            return None
        values.extend(items)
    return values


def _setup_keywords(tree: ast.Module) -> dict[str, ast.expr] | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _call_name(node.func) in _SETUP_CALLS:
            return {kw.arg: kw.value for kw in node.keywords if kw.arg}
    return None


def parse_setup_py(path: Path) -> tuple[list[Package], bool]:
    """Return ``(packages, declares_install_requires)`` from literal ``setup()`` arguments."""
    try:
        tree = ast.parse(read_text_limited(path, errors="replace"), filename=str(path))
    except (OSError, ValueError, SyntaxError) as exc:
        logger.debug("Failed to parse setup.py at %s: %s", path, exc)
        _gap(path, "setup.py could not be read or parsed; Python dependencies were not scanned")
        return [], False
    keywords = _setup_keywords(tree)
    if keywords is None:
        return [], False
    bindings = _literal_bindings(tree)
    values: list[str] = []
    dynamic: list[str] = []
    for key, reader in (("install_requires", _string_list), ("extras_require", _extras_lists)):
        if key not in keywords:
            continue
        found = reader(keywords[key], bindings)
        if found is None:
            dynamic.append(key)
        else:
            values.extend(found)
    if dynamic:
        _gap(path, f"setup.py computes {', '.join(dynamic)} dynamically; those dependencies were not scanned")
    packages, malformed = _packages_from_strings(values)
    if malformed:
        _gap(path, "setup.py contains malformed requirement entries; Python dependency coverage is partial")
    return packages, "install_requires" in keywords


def parse_setup_manifests(directory: Path) -> tuple[list[Package], bool]:
    """Packages from ``setup.cfg`` and ``setup.py``; second value: either declares install_requires."""
    packages: list[Package] = []
    declared = False
    for name, parser in (("setup.cfg", parse_setup_cfg), ("setup.py", parse_setup_py)):
        path = directory / name
        if path.is_file():
            found, has_requires = parser(path)
            packages.extend(found)
            declared = declared or has_requires
    unique = {pkg.name.lower(): pkg for pkg in reversed(packages)}
    return list(reversed(unique.values())), declared


def _pyproject_dynamic_dependencies(path: Path) -> bool:
    if not path.is_file():
        return False
    try:
        data = tomllib.loads(read_text_limited(path, errors="replace"))
    except (OSError, ValueError):
        return False
    dynamic = (data.get("project") or {}).get("dynamic") or []
    return isinstance(dynamic, list) and "dependencies" in dynamic


def setup_declared_packages(directory: Path) -> list[Package]:
    """Fallback for projects without a lockfile, requirements.txt or static pyproject deps."""
    packages, declared = parse_setup_manifests(directory)
    pyproject = directory / "pyproject.toml"
    if not declared and _pyproject_dynamic_dependencies(pyproject):
        _gap(
            pyproject,
            "pyproject.toml declares dynamic dependencies and no static setup.cfg/setup.py install_requires was found; "
            "Python dependencies were not scanned",
        )
    return packages
