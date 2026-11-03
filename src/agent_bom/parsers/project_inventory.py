"""Dependency coverage and bounded first-party context for an explicit project."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from agent_bom.models import Package
from agent_bom.parsers.repository.artifacts import RepositoryReader
from agent_bom.parsers.repository.workspaces import workspace_context


def _directory_record(root: Path, directory: Path, packages: list[Package], manifests: frozenset[str], locks: frozenset[str]) -> dict:
    files = sorted(name for name in manifests if (directory / name).exists())
    lockfiles = [name for name in files if name in locks]
    direct = sum(1 for pkg in packages if pkg.is_direct)
    return {
        "path": "." if directory == root else str(directory.relative_to(root)),
        "package_count": len(packages),
        "direct_packages": direct,
        "transitive_packages": len(packages) - direct,
        "manifest_files": files,
        "lockfile_files": lockfiles,
        "declaration_files": [name for name in files if name not in locks],
        "advisory_evidence": "lockfile_backed" if lockfiles else "declaration_only",
        "ecosystems": dict(Counter(pkg.ecosystem for pkg in packages)),
    }


def summarize_project_inventory(
    root: Path, dir_map: dict[Path, list[Package]], manifest_names: frozenset[str], lockfile_names: frozenset[str]
) -> dict[str, object]:
    """Preserve dependency coverage while adding bounded local workspace declarations."""
    root = Path(root).resolve()
    directories = [
        _directory_record(root, directory, packages, manifest_names, lockfile_names)
        for directory, packages in sorted(dir_map.items(), key=lambda item: str(item[0]))
    ]
    ecosystems: Counter[str] = Counter()
    for record in directories:
        ecosystems.update(record["ecosystems"])
    backed = [r for r in directories if r["lockfile_files"]]
    declared = [r for r in directories if not r["lockfile_files"]]
    packages = sum(r["package_count"] for r in directories)
    locked = sum(r["package_count"] for r in backed)
    manifest_files = sum(len(r["manifest_files"]) for r in directories)
    lockfiles = sum(len(r["lockfile_files"]) for r in directories)
    return {
        "root": str(root),
        "repository_context": workspace_context(RepositoryReader(root)),
        "manifest_directories": len(dir_map),
        "lockfile_directories": len(backed),
        "declaration_only_directories": len(declared),
        "manifest_files": manifest_files,
        "lockfiles": lockfiles,
        "declaration_only_files": manifest_files - lockfiles,
        "package_count": packages,
        "direct_packages": sum(r["direct_packages"] for r in directories),
        "transitive_packages": sum(r["transitive_packages"] for r in directories),
        "lockfile_backed_packages": locked,
        "declaration_only_packages": packages - locked,
        "lockfile_backed_direct_packages": sum(r["direct_packages"] for r in backed),
        "lockfile_backed_transitive_packages": sum(r["transitive_packages"] for r in backed),
        "declaration_only_direct_packages": sum(r["direct_packages"] for r in declared),
        "declaration_only_transitive_packages": sum(r["transitive_packages"] for r in declared),
        "advisory_depth_pct": round(locked / packages * 100) if packages else 0,
        "ecosystems": dict(ecosystems),
        "directories": directories,
    }
