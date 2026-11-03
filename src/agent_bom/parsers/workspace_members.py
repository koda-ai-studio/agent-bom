"""Names of the packages a repository builds itself (workspace root and members).

A monorepo's own packages are first-party: they are never "undeclared" third-party
dependencies of the code that imports them. Reads uv (``[tool.uv.workspace]``),
npm/yarn (``package.json`` ``workspaces``), pnpm (``pnpm-workspace.yaml``) and
cargo (``[workspace] members``) metadata. Unreadable metadata contributes nothing.
"""

from __future__ import annotations

import json
import tomllib
from pathlib import Path
from typing import Any

from agent_bom.core.packages import normalize_package_name
from agent_bom.parsers.file_limits import read_text_limited

_MAX_MEMBERS = 500


def _toml(path: Path) -> dict[str, Any]:
    try:
        data = tomllib.loads(read_text_limited(path))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(read_text_limited(path))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _member_dirs(root: Path, patterns: object) -> list[Path]:
    if not isinstance(patterns, list):
        return []
    resolved_root = root.resolve()
    found: list[Path] = []
    for pattern in patterns:
        if not isinstance(pattern, str) or not pattern.strip() or pattern.startswith(("/", "!")) or ".." in pattern:
            continue
        for candidate in sorted(root.glob(pattern.strip().removeprefix("./").rstrip("/"))):
            if len(found) >= _MAX_MEMBERS:
                return found
            try:
                inside = candidate.is_dir() and not candidate.is_symlink() and candidate.resolve().is_relative_to(resolved_root)
            except OSError:
                inside = False
            if inside:
                found.append(candidate)
    return found


def _pnpm_patterns(path: Path) -> list[str]:
    try:
        import yaml

        data = yaml.safe_load(read_text_limited(path))
    except Exception:  # noqa: BLE001 - malformed workspace metadata contributes nothing
        return []
    packages = data.get("packages") if isinstance(data, dict) else None
    return [p for p in packages if isinstance(p, str)] if isinstance(packages, list) else []


def _pypi_names(root: Path) -> set[str]:
    data = _toml(root / "pyproject.toml")
    names = [data.get("project", {}).get("name")]
    workspace = data.get("tool", {}).get("uv", {}).get("workspace")
    if isinstance(workspace, dict):
        names += [
            _toml(member / "pyproject.toml").get("project", {}).get("name") for member in _member_dirs(root, workspace.get("members"))
        ]
    return {normalize_package_name(n, "pypi") for n in names if isinstance(n, str) and n.strip()}


def _npm_names(root: Path) -> set[str]:
    manifest = _json(root / "package.json")
    workspaces = manifest.get("workspaces")
    patterns = workspaces.get("packages") if isinstance(workspaces, dict) else workspaces
    pattern_list = [p for p in patterns if isinstance(p, str)] if isinstance(patterns, list) else []
    if (root / "pnpm-workspace.yaml").is_file():
        pattern_list += _pnpm_patterns(root / "pnpm-workspace.yaml")
    names = [manifest.get("name")] + [_json(member / "package.json").get("name") for member in _member_dirs(root, pattern_list)]
    return {n.strip() for n in names if isinstance(n, str) and n.strip()}


def _cargo_names(root: Path) -> set[str]:
    data = _toml(root / "Cargo.toml")
    names = [data.get("package", {}).get("name")]
    workspace = data.get("workspace")
    if isinstance(workspace, dict):
        names += [_toml(member / "Cargo.toml").get("package", {}).get("name") for member in _member_dirs(root, workspace.get("members"))]
    return {n.strip() for n in names if isinstance(n, str) and n.strip()}


def first_party_package_names(root: Path) -> dict[str, set[str]]:
    """``{ecosystem: names}`` for the packages *root* builds (pypi names normalized)."""
    root = Path(root)
    return {"pypi": _pypi_names(root), "npm": _npm_names(root), "cargo": _cargo_names(root)}


def first_party_frameworks(root: Path, framework_by_package: dict[str, str]) -> frozenset[str]:
    """Framework keys whose PyPI package is the repository's own workspace root or member."""
    first_party = _pypi_names(Path(root))
    return frozenset(key for package, key in framework_by_package.items() if normalize_package_name(package, "pypi") in first_party)
