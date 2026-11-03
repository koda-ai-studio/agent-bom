"""Go workspace dependency collection bounded by the selected project root."""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

from agent_bom.coverage import record_manifest_parse_warning
from agent_bom.models import Package
from agent_bom.parsers.repository.artifacts import RepositoryReader


def _safe_member(root: Path, directory: Path) -> bool:
    try:
        if not directory.resolve().is_relative_to(root):
            return False
        if any(p.is_symlink() for p in [directory, *directory.parents] if p != root and p.is_relative_to(root)):
            return False
        for name, limit in (("go.mod", 2 * 1024 * 1024), ("go.sum", 16 * 1024 * 1024)):
            path = directory / name
            if path.is_symlink() or (path.exists() and path.stat().st_size > limit):
                return False
        return directory.is_dir()
    except OSError:
        return False


def _paths(text: str) -> list[str]:
    paths = []
    for block in re.finditer(r"use\s*\(([^)]+)\)", text, re.DOTALL):
        paths += [line.split("//", 1)[0].strip().strip('"') for line in block.group(1).splitlines() if line.split("//", 1)[0].strip()]
    paths += [match.group(1).strip('"') for match in re.finditer(r"^use\s+([^\s(]+)", text, re.MULTILINE)]
    return list(dict.fromkeys(paths))


def parse_go_workspace_members(directory: Path, parse_packages: Callable[[Path], list[Package]]) -> list[Package]:
    root = directory.resolve()
    reader = RepositoryReader(root)
    text = reader.read("go.work")

    def warn(detail: str) -> None:
        record_manifest_parse_warning(ecosystem="go", path=str(root / "go.work"), detail=detail)

    if text is None:
        if reader.unresolved:
            warn("go.work could not be read safely within the parser limit; Go workspace coverage is partial")
        return []
    paths = _paths(text)
    if len(paths) > 500:
        warn("Go workspace member limit reached; dependency coverage is partial")
    direct: dict[tuple[str, str], Package] = {}
    indirect: dict[tuple[str, str], Package] = {}
    for path in paths[:500]:
        member = root / path
        if not _safe_member(root, member):
            warn("Go workspace member outside the project boundary, unreadable or over the artifact limit was not scanned")
            continue
        for pkg in parse_packages(member):
            key = (pkg.name, pkg.version)
            if pkg.is_direct:
                direct[key] = pkg
            else:
                indirect.setdefault(key, pkg)
    return list({**indirect, **direct}.values())
