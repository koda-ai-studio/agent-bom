"""Supplement pre-Go-1.17 go.mod inventories with the modules recorded in go.sum.

Go 1.17 introduced module graph pruning: from then on go.mod lists every module
that provides a package to the main module, so go.mod is the authority. Before
1.17 (or with no ``go`` directive) go.mod carries only direct requirements and
the transitive build list is visible only in go.sum. Lines hashing a module zip
(``mod v1.2.3 h1:...``) mean the module source was downloaded for the build;
``/go.mod``-only lines were read for version selection and are not inventory.
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_bom.core.versions.go import _compare_go_versions
from agent_bom.models import Package

_GO_DIRECTIVE = re.compile(r"^go[ \t]+(\d+)\.(\d+)", re.MULTILINE)
_MODULE_DIRECTIVE = re.compile(r"^module[ \t]+(\S+)", re.MULTILINE)
PRUNED_GRAPH_MIN = (1, 17)


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


def go_sum_zip_modules(go_sum: Path) -> dict[str, str]:
    """Map each module path with a zip hash in go.sum to its highest recorded version."""
    selected: dict[str, str] = {}
    try:
        lines = go_sum.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return selected
    for line in lines:
        parts = line.split()
        if len(parts) != 3 or not parts[2].startswith("h1:") or parts[1].endswith("/go.mod"):
            continue
        module, version = parts[0], parts[1]
        current = selected.get(module)
        if current is None or (_compare_go_versions(version, current) or 0) > 0:
            selected[module] = version
    return selected


def supplement_from_go_sum(go_mod: Path, go_sum: Path, known: set[str], replaced: set[str]) -> list[Package]:
    """Return transitive modules go.sum records that a pre-1.17 go.mod does not list."""
    if not go_sum.exists() or go_mod_lists_full_graph(go_mod):
        return []
    skip = known | replaced | {_main_module(go_mod)}
    packages = []
    for module, version in sorted(go_sum_zip_modules(go_sum).items()):
        if module in skip:
            continue
        packages.append(
            Package(
                name=module,
                version=version[1:] if version.startswith("v") else version,
                ecosystem="go",
                purl=f"pkg:golang/{module}@{version}",
                is_direct=False,
                version_source="lockfile",
                version_evidence=[{"type": "lockfile", "source_file": str(go_sum), "parser": "go.sum (pre-1.17 module graph)"}],
            )
        )
    return packages
