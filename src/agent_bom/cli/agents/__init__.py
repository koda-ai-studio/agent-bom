"""CLI agents scan command — re-exports for patch targets and public surface."""

from typing import TYPE_CHECKING, Any

from agent_bom.cli.agents._preflight import emit_dry_run_plan
from agent_bom.cli.agents._self_scan import _build_self_scan_inventory
from agent_bom.cli.agents.scan_cmd import _expand_docker_mcp_packages, scan
from agent_bom.discovery import discover_all
from agent_bom.parsers import extract_packages
from agent_bom.resolver import resolve_all_versions_sync

if TYPE_CHECKING:
    from agent_bom.scanners.package_scan import scan_agents_sync

__all__ = [
    "_build_self_scan_inventory",
    "_expand_docker_mcp_packages",
    "discover_all",
    "emit_dry_run_plan",
    "extract_packages",
    "resolve_all_versions_sync",
    "scan",
    "scan_agents_sync",
]


def __getattr__(name: str) -> Any:
    # Resolved on first use so building the command tree (--help) does not
    # import the vulnerability-matching stack.
    if name == "scan_agents_sync":
        from agent_bom.scanners.package_scan import scan_agents_sync

        return scan_agents_sync
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
