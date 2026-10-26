"""Complete an unlocked Python project's dependency inventory.

Trust ladder; the first rung that applies wins (lockfiles are handled earlier,
in ``parse_pip_packages``):

1. lockfile — exact (not here);
2. the project's own virtualenv — exact installed versions, offline;
3. network allowed — declared ranges resolved transitively from PyPI metadata
   for the documented target in :mod:`agent_bom.parsers.pypi_resolution`;
4. offline — a coverage gap: transitive dependencies are not resolved.

Only requirements that truly cannot be resolved are reported as a gap.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from agent_bom.coverage import record_manifest_parse_warning, record_scan_note
from agent_bom.http_client import is_offline
from agent_bom.models import Package
from agent_bom.parsers.file_limits import read_text_limited
from agent_bom.parsers.pypi_resolution import ResolvedDistribution, requirement_applies, resolve_requirements
from agent_bom.parsers.python_venv import InstalledDistribution, find_project_venv, read_venv

_ADVICE = "add a lockfile or scan inside the project's virtualenv; Python dependency coverage is partial"
OFFLINE_GAP = "transitive dependencies not resolved offline; " + _ADVICE
RESOLVED_NOTE = (
    "resolved at scan time from declared ranges; versions may differ from your install — add a lockfile for exact results "
    "(environment markers evaluated for CPython 3.12 on Linux x86_64)"
)
_RESOLVED_REASON = "resolved at scan time from declared ranges; not a pinned or installed version"


def _gap(manifest: Path, detail: str) -> None:
    record_manifest_parse_warning(ecosystem="pypi", path=str(manifest), detail=f"{manifest.name}: {detail}")


def _evidence(package: Package, kind: str, key: str) -> str:
    found = next((e for e in package.version_evidence if e.get("type") == kind), None)
    return str(found.get(key) or "") if found else ""


def declared_requirement(package: Package) -> Requirement | None:
    """Rebuild the PEP 508 requirement a declared package came from; ``None`` for URL/git references."""
    declared = package.declared_version or ""
    if "://" in declared or declared.startswith("git"):
        return None
    if not declared and package.version not in ("", "unknown", "latest"):
        declared = f"=={package.version}"
    extras = _evidence(package, "requirement_extras", "extras")
    marker = _evidence(package, "environment_marker", "marker")
    text = package.name + (f"[{extras}]" if extras else "") + declared + (f"; {marker}" if marker else "")
    try:
        return Requirement(text)
    except InvalidRequirement:
        return None


def _applies(package: Package) -> bool:
    requirement = declared_requirement(package)
    return requirement is None or requirement_applies(requirement)


def _project_name(directory: Path) -> str | None:
    try:
        data = tomllib.loads(read_text_limited(directory / "pyproject.toml"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    name = data.get("project", {}).get("name") if isinstance(data.get("project"), dict) else None
    return canonicalize_name(name) if isinstance(name, str) and name else None


def _installed(package: Package | None, dist: InstalledDistribution) -> Package:
    evidence = {"type": "installed_metadata", "source_file": str(dist.metadata_path), "parser": "python_venv"}
    if package is None:
        package = Package(
            name=dist.name,
            version=dist.version,
            ecosystem="pypi",
            is_direct=False,
            dependency_scope="unknown",
            reachability_evidence="installed_environment",
        )
    package.version = dist.version
    package.purl = f"pkg:pypi/{dist.name}@{dist.version}"
    package.resolved_version = dist.version
    package.version_source = "installed_environment"
    package.version_confidence = "exact"
    package.floating_reference = False
    package.floating_reference_reason = None
    package.version_evidence = [evidence, *package.version_evidence]
    return package


def _from_venv(directory: Path, venv: Path, manifest: Path, declared: list[Package]) -> list[Package]:
    inventory = read_venv(venv, directory.resolve())
    project = _project_name(directory)
    by_name = {canonicalize_name(p.name): p for p in declared}
    installed = {canonicalize_name(d.name): d for d in inventory.distributions if canonicalize_name(d.name) != project}
    packages = [_installed(by_name.get(key), dist) for key, dist in installed.items()]
    missing = [p for key, p in by_name.items() if key not in installed]
    packages.extend(missing)
    absent = sorted(p.name for p in missing if _applies(p))
    if absent:
        names = ", ".join(absent)
        _gap(manifest, f"transitive dependencies not resolved for {names} (declared but not installed in {venv.name}); {_ADVICE}")
    if inventory.truncated:
        _gap(manifest, f"{venv.name} holds more installed distributions than the scan reads; {_ADVICE}")
    return packages


def _resolved_package(dist: ResolvedDistribution, declared: Package | None) -> Package:
    package = declared or Package(
        name=dist.name,
        version=dist.version,
        ecosystem="pypi",
        is_direct=False,
        parent_package=dist.parent,
        dependency_depth=dist.depth,
        declared_version=dist.constraint or None,
        reachability_evidence="declaration_only",
    )
    package.version = dist.version
    package.purl = f"pkg:pypi/{package.name}@{dist.version}"
    package.resolved_version = dist.version
    package.resolved_from_registry = True
    package.version_source = "resolved_at_scan"
    package.version_confidence = "medium"
    package.floating_reference = True
    package.floating_reference_reason = _RESOLVED_REASON
    return package


def _from_registry(manifest: Path, declared: list[Package]) -> list[Package]:
    roots: dict[str, Requirement] = {}
    failures: dict[str, str] = {}
    for package in declared:
        requirement = declared_requirement(package)
        if requirement is None:
            failures[package.name] = "URL or git reference; not resolved"
        elif requirement_applies(requirement):
            roots[canonicalize_name(package.name)] = requirement
    result = resolve_requirements(list(roots.values()))
    by_name: dict[str, Package] = {canonicalize_name(p.name): p for p in declared}
    packages = [p for key, p in by_name.items() if key not in result.resolved]
    packages += [_resolved_package(dist, by_name.get(key) if key in roots else None) for key, dist in result.resolved.items()]
    failures |= result.failures
    if result.resolved:
        record_scan_note(ecosystem="pypi", path=str(manifest), reason="resolved_at_scan", detail=f"{manifest.name}: {RESOLVED_NOTE}")
    if failures:
        reasons = "; ".join(f"{name}: {reason}" for name, reason in sorted(failures.items()))
        _gap(manifest, f"transitive dependencies not resolved for {reasons}; {_ADVICE}")
    return packages


def complete_unlocked_python(directory: Path, manifest: Path, declared: list[Package]) -> list[Package]:
    """Apply ladder rungs 2-4 to *declared* packages read from an unlocked *manifest*."""
    venv = find_project_venv(directory)
    if venv is not None:
        return _from_venv(directory, venv, manifest, declared)
    if is_offline():
        _gap(manifest, OFFLINE_GAP)
        return declared
    return _from_registry(manifest, declared)
