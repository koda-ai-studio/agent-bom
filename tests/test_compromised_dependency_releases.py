"""No dependency range or lockfile admits a release known to be maliciously published.

Lockfile installs are safe by construction; this guards installs made without
the lock (``pip install 'agent-bom[ai-enrich]'``), which resolve from the ranges.
litellm 1.107.0 wheels shipped a startup-hook credential stealer (2026-10-21).
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

ROOT = Path(__file__).resolve().parents[1]
COMPROMISED = {"litellm": ("1.107.0",)}


def _requirements() -> list[tuple[str, Requirement]]:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    groups = {"dependencies": project["project"].get("dependencies", [])}
    groups.update({f"extra:{name}": deps for name, deps in project["project"].get("optional-dependencies", {}).items()})
    groups.update({f"group:{name}": deps for name, deps in project.get("dependency-groups", {}).items()})
    groups["uv-override"] = project.get("tool", {}).get("uv", {}).get("override-dependencies", [])
    return [(where, Requirement(spec)) for where, specs in groups.items() for spec in specs if isinstance(spec, str)]


def test_no_dependency_range_admits_a_compromised_release() -> None:
    admitted = [
        f"{where}: {requirement} admits {version}"
        for where, requirement in _requirements()
        for version in COMPROMISED.get(canonicalize_name(requirement.name), ())
        if requirement.specifier.contains(Version(version), prereleases=True)
    ]
    assert admitted == []


def test_the_lockfile_never_resolves_a_compromised_release() -> None:
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    resolved = [
        f"{package['name']} {package['version']}"
        for package in lock.get("package", [])
        if package.get("version") in COMPROMISED.get(canonicalize_name(package["name"]), ())
    ]
    assert resolved == []


def test_the_guard_covers_a_declared_dependency() -> None:
    declared = {canonicalize_name(requirement.name) for _where, requirement in _requirements()}
    assert set(COMPROMISED) <= declared
