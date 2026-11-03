"""Reconstruct the pre-Go-1.17 build list from go.mod and go.sum.

Go 1.17 introduced module graph pruning: from then on go.mod lists every module
that provides a package to the main module, so go.mod is the authority. Before
1.17 (or with no ``go`` directive) go.mod carries only direct requirements and
the rest of the module graph is visible only in go.sum.

``go list -m all`` (the build list vulnerability matching should mirror) selects
the highest version of every module path in the graph, and a tidy go.sum records
each graph member: ``mod v1.2.3 h1:`` when the module zip was downloaded,
``mod v1.2.3/go.mod h1:`` when only its go.mod was read for version selection.
The highest version recorded per path therefore reproduces the build list. A
module whose selected version has only a ``/go.mod`` line is still a build-list
member, but no code of it is compiled; it is kept for advisory matching and
marked ``declaration_only`` with ``build_list_role: module_graph_only``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from agent_bom.core.versions.go import _compare_go_versions
from agent_bom.models import Package

_GO_DIRECTIVE = re.compile(r"^go[ \t]+(\d+)\.(\d+)", re.MULTILINE)
_MODULE_DIRECTIVE = re.compile(r"^module[ \t]+(\S+)", re.MULTILINE)
PRUNED_GRAPH_MIN = (1, 17)
_GO_MOD_SUFFIX = "/go.mod"


@dataclass(frozen=True)
class Selection:
    version: str
    has_zip: bool


def go_mod_lists_full_graph(go_mod: Path) -> bool:
    """True when the go.mod ``go`` directive is 1.17 or later."""
    try:
        content = go_mod.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return True
    match = _GO_DIRECTIVE.search(content)
    if match is None:
        return False
    return (int(match.group(1)), int(match.group(2))) >= PRUNED_GRAPH_MIN


def _main_module(go_mod: Path) -> str | None:
    try:
        match = _MODULE_DIRECTIVE.search(go_mod.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return None
    return match.group(1).strip('"') if match else None


def _newer(candidate: str, current: str) -> bool:
    return (_compare_go_versions(candidate, current) or 0) > 0


def go_sum_build_list(go_sum: Path) -> dict[str, Selection]:
    """Map each module path in go.sum to its highest recorded version and whether that version's zip is hashed."""
    versions: dict[str, str] = {}
    zips: set[tuple[str, str]] = set()
    try:
        lines = go_sum.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return {}
    for line in lines:
        parts = line.split()
        if len(parts) != 3 or not parts[2].startswith("h1:"):
            continue
        module, raw = parts[0], parts[1]
        version = raw.removesuffix(_GO_MOD_SUFFIX)
        if version == raw:
            zips.add((module, version))
        current = versions.get(module)
        if current is None or _newer(version, current):
            versions[module] = version
    return {module: Selection(version, (module, version) in zips) for module, version in versions.items()}


def _bare(version: str) -> str:
    return version[1:] if version.startswith("v") else version


def _graph_package(module: str, selection: Selection, go_sum: Path) -> Package:
    role = "module_zip" if selection.has_zip else "module_graph_only"
    parser = "go.sum (pre-1.17 build list)" if selection.has_zip else "go.sum (pre-1.17 module graph, no code in build)"
    return Package(
        name=module,
        version=_bare(selection.version),
        ecosystem="go",
        purl=f"pkg:golang/{module}@{selection.version}",
        is_direct=False,
        version_source="lockfile",
        version_confidence="high",
        reachability_evidence="lockfile" if selection.has_zip else "declaration_only",
        version_evidence=[{"type": "lockfile", "source_file": str(go_sum), "parser": parser, "build_list_role": role}],
    )


def _raise_to_selection(pkg: Package, selection: Selection) -> None:
    if not _newer(selection.version, f"v{pkg.version}"):
        return
    required = pkg.version
    pkg.version = _bare(selection.version)
    pkg.purl = f"pkg:golang/{pkg.name}@{selection.version}"
    pkg.declared_version = required
    pkg.resolved_version = pkg.version
    pkg.version_conflicts = [{"source": "go.mod require", "version": required, "selected_by": "go.sum build list"}]


def apply_pre_117_build_list(go_mod: Path, go_sum: Path, packages: list[Package], replace_map: dict[str, tuple[str, str]]) -> list[Package]:
    """Align a pre-1.17 go.mod inventory with the build list and return the graph modules go.mod omits.

    Replace sources and targets keep the version the replace directive fixes;
    they are neither raised nor supplemented.
    """
    if not go_sum.exists() or go_mod_lists_full_graph(go_mod):
        return []
    replaced = set(replace_map) | {target for target, _ in replace_map.values()}
    build_list = go_sum_build_list(go_sum)
    for pkg in packages:
        if pkg.name in build_list and pkg.name not in replaced:
            _raise_to_selection(pkg, build_list[pkg.name])
    skip = {pkg.name for pkg in packages} | replaced | {_main_module(go_mod)}
    return [_graph_package(module, selection, go_sum) for module, selection in sorted(build_list.items()) if module not in skip]
