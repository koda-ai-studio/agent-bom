"""Decide whether a framework import root is the SDK or a module the project ships itself.

``from agents.agent import Agent`` is the OpenAI Agents SDK in one repository
and a local ``agents/`` package in the next. Import names alone cannot tell
them apart, so framework evidence needs one of two facts: the SDK's package is
declared by the project, or no local module of that name shadows the import.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from agent_bom.core.packages import normalize_package_name
from agent_bom.parsers.declared_requirements import parse_pyproject_dependencies, parse_requirements_txt
from agent_bom.traversal import iter_discovery_files


def declared_python_requirements(project: Path) -> dict[str, str]:
    """``{package: version}`` from every requirement file in the project.

    Traversal prunes vendored/generated directories and nested VCS worktrees so
    a repository that keeps agent worktrees (each a full nested checkout) does
    not re-count every manifest once per worktree.
    """
    pkgs: dict[str, str] = {}
    if not project.is_dir():
        return pkgs
    for path in iter_discovery_files(project):
        try:
            if path.name.startswith("requirements") and path.name.endswith(".txt"):
                pkgs.update(parse_requirements_txt(path))
            elif path.name == "pyproject.toml":
                pkgs.update(parse_pyproject_dependencies(path))
        except OSError:
            continue
    return pkgs


def declared_python_packages(project: Path) -> frozenset[str]:
    """Normalized names of every package the project's requirement files declare."""
    return frozenset(normalize_package_name(name, "pypi") for name in declared_python_requirements(project))


def _has_python_source(directory: Path) -> bool:
    try:
        return any(child.suffix == ".py" for child in directory.iterdir())
    except OSError:
        return False


def local_module_shadows(root_name: str, importing_file: Path, project_root: Path) -> bool:
    """True when ``root_name`` resolves to a module next to ``importing_file`` or between it and the project root.

    Python resolves a bare import from the running script's directory first,
    and repositories commonly ``sys.path.insert`` the project root, so both the
    importing file's directory and every ancestor up to the project root count.
    """
    first = root_name.split(".")[0]
    if not first:
        return False
    directories: list[Path] = [importing_file.parent]
    try:
        relative = importing_file.resolve().relative_to(project_root.resolve())
        directories = [project_root / parent for parent in relative.parents]
    except (ValueError, OSError):
        # Keep the default fallback (importing_file.parent) when paths cannot
        # be resolved/relativized (e.g., file outside project root or FS errors).
        pass
    for directory in dict.fromkeys(directories):
        if (directory / f"{first}.py").is_file():
            return True
        package = directory / first
        if package.is_dir() and ((package / "__init__.py").is_file() or _has_python_source(package)):
            return True
    return False


def is_sdk_import(
    root_name: str,
    package_names: Iterable[str],
    importing_file: Path,
    project_root: Path,
    declared: frozenset[str],
) -> bool:
    """A framework import is SDK evidence unless a local module shadows it and no SDK package is declared."""
    if any(normalize_package_name(package, "pypi") in declared for package in package_names):
        return True
    return not local_module_shadows(root_name, importing_file, project_root)
