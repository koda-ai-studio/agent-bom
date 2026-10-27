"""Every module under src/agent_bom is reachable from the shipped product.

A module counts as reachable when another src module imports it (statically,
relatively, or by its dotted name in a lazy-import table) or a pyproject entry
point names it. Anything else is dead weight that tests keep green while no
user path runs it. Modules that are legitimately launched another way, or are
waiting on an owner decision, sit in ``ALLOWED_UNIMPORTED`` with the reason.
The allowlist only shrinks: an entry that is imported again, or deleted, fails.
"""

from __future__ import annotations

import ast
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

ALLOWED_UNIMPORTED: dict[str, str] = {
    # Launched with `python -m`.
    "agent_bom.deploy_k8s_cleanup": "Helm teardown hook (deploy/helm/agent-bom/templates/teardown-hook-job.yaml)",
    "agent_bom.deployment_probe": "scripts/deploy/probe_with_oauth.py",
    "agent_bom.runtime_smoke_mcp": "smoke MCP server in docs/RUNTIME_REFERENCE.md and the runtime evidence pack",
    "agent_bom.api.storage.registry_import": "operator recovery tool, docs/operations/sqlite-registry-import.md",
    "agent_bom.api.storage.finding_history_cli": "history backfill, docs/decisions/015-materialized-scan-finding-snapshots.md",
    "agent_bom.cloud.native_inventory_cli": "isolated native export, docs/cloud/NATIVE_METADATA_EXPORT.md",
    # Imported by maintainer scripts.
    "agent_bom.accuracy_baseline": "scripts/generate_accuracy_baseline.py",
    "agent_bom.deploy_profiles": "scripts/validate_helm_profiles.py and scripts/install_helm_profile.py",
    "agent_bom.graph.investigation_measurement": "scripts/evaluate_investigation.py",
    # Built but not wired into any product path; awaiting an owner decision.
    "agent_bom.api.tenant_binding": "tenant-binding primitive, not yet enforced on any route",
    "agent_bom.graph.remediation_receipts": "documented remediation receipts, never produced",
    "agent_bom.intel_fetch": "governed raw-intel fetch lane described in docs/DATA_MODEL.md, no caller",
    "agent_bom.scanners.intel_advisory": "Intel PSIRT seeds advertised in docs/EXPERIMENTAL.md, never run by a scan",
    "agent_bom.ticketing.oauth": "Jira OAuth 3LO helpers; the connect and refresh flows are not wired",
    # Imported only by tests; not yet triaged.
    "agent_bom.ci_detect": "test-only",
    "agent_bom.core.egress_hosts": "test-only",
    "agent_bom.orchestration": "test-only",
    "agent_bom.red_team_llm": "test-only",
    "agent_bom.routing": "test-only",
    "agent_bom.trust_score": "test-only",
}

_DOTTED = re.compile(r"agent_bom(?:\.[A-Za-z_]\w*)+")
_RELATIVE = re.compile(r"\.[A-Za-z_][\w.]*")


def _module_name(path: Path) -> str:
    parts = list(path.relative_to(SRC).with_suffix("").parts)
    return ".".join(parts[:-1] if parts[-1] == "__init__" else parts)


def _modules() -> dict[str, Path]:
    return {_module_name(path): path for path in (SRC / "agent_bom").rglob("*.py")}


def _references(name: str, path: Path) -> set[str]:
    package = name if path.name == "__init__.py" else name.rpartition(".")[0]
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = package.split(".")[: len(package.split(".")) - node.level + 1] if node.level else []
            target = ".".join([*base, *([node.module] if node.module else [])])
            found.add(target)
            found.update(f"{target}.{alias.name}" for alias in node.names)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            found.update(_DOTTED.findall(node.value))
            if _RELATIVE.fullmatch(node.value):
                found.add(package + node.value)
    return found


def _entry_point_modules() -> set[str]:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    targets = list(project.get("scripts", {}).values())
    for group in project.get("entry-points", {}).values():
        targets.extend(group.values())
    return {target.split(":", 1)[0] for target in targets}


def _unimported() -> set[str]:
    modules = _modules()
    referenced = set(_entry_point_modules())
    for name, path in modules.items():
        for reference in _references(name, path) - {name}:
            parts = reference.split(".")
            referenced.update(".".join(parts[:index]) for index in range(1, len(parts) + 1))
    return {name for name, path in modules.items() if path.name not in {"__init__.py", "__main__.py"} and name not in referenced}


def test_every_module_is_imported_or_allowlisted() -> None:
    orphans = sorted(_unimported() - set(ALLOWED_UNIMPORTED))
    assert not orphans, (
        "modules nothing in src imports and no entry point names — delete them, wire them, "
        f"or add them to ALLOWED_UNIMPORTED with the reason: {orphans}"
    )


def test_unimported_allowlist_only_shrinks() -> None:
    unimported = _unimported()
    stale = sorted(name for name in ALLOWED_UNIMPORTED if name not in unimported)
    assert not stale, f"remove from ALLOWED_UNIMPORTED (now imported or deleted): {stale}"


def test_guard_sees_relative_dotted_and_lazy_imports(tmp_path: Path) -> None:
    source = 'from .sibling import x\nfrom .. import parent_mod\nLAZY = {"name": "agent_bom.lazy.target"}\nREL = ".relative_target"\n'
    module = tmp_path / "mod.py"
    module.write_text(source, encoding="utf-8")
    refs = _references("agent_bom.pkg.mod", module)
    assert {"agent_bom.pkg.sibling", "agent_bom.parent_mod", "agent_bom.lazy.target", "agent_bom.pkg.relative_target"} <= refs
