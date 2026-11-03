"""``--exclude-dev`` / ``--prod-only``: drop development-only packages before matching.

Filtering the inventory once, before vulnerability matching, keeps every
downstream surface consistent: findings, gates, SARIF, SBOMs, JSON and the
console all see the same production scope. Only packages a lockfile placed in
a development scope are dropped; ``runtime`` and ``unknown`` scopes stay, so
an unlabelled package is never silently hidden. The exclusion is recorded as
a scan note so the report states its own scope.
"""

from __future__ import annotations

from typing import Any

from agent_bom.coverage import record_scan_note
from agent_bom.domain.inventory_types import DEV_DEPENDENCY_SCOPES


def is_dev_package(package: Any) -> bool:
    return str(getattr(package, "dependency_scope", "") or "").strip().lower() in DEV_DEPENDENCY_SCOPES


def exclude_dev_packages(agents: list[Any]) -> int:
    """Remove development-only packages from every server; return how many were removed."""
    removed = 0
    for agent in agents:
        for server in agent.mcp_servers:
            kept = [package for package in server.packages if not is_dev_package(package)]
            removed += len(server.packages) - len(kept)
            server.packages = kept
    return removed


def apply_dependency_scope(opts: Any, st: Any) -> None:
    if not getattr(opts, "exclude_dev", False):
        return
    removed = exclude_dev_packages(st.agents)
    st.total_packages = max(0, st.total_packages - removed)
    record_scan_note(
        ecosystem="dependency-scope",
        path="--exclude-dev",
        reason="operator_scope",
        detail=f"--exclude-dev removed {removed} development-only package(s) before matching; "
        "findings and gates cover production scope only.",
    )
    if not opts.quiet:
        st.con.print(f"  [dim]Excluded {removed} development-only package(s) (--exclude-dev)[/dim]")
