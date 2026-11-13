"""The report object an MCP ``scan`` call renders, with its own scan id."""

from __future__ import annotations

import uuid
from typing import Any

from agent_bom.parsers.sbom_context import imported_cloud_inventory
from agent_bom.scanners import local_data_freshness
from agent_bom.scanners.mcp_audit import attach_passive_mcp_audit


def build_scan_report(report_cls: Any, agents: list, blast_radii: list, scan_sources: list[str], *, offline: bool) -> Any:
    """A report for one MCP scan call; each call is its own scan, so it gets a fresh id."""
    report = report_cls(
        agents,
        blast_radii,
        cloud_inventory_data=imported_cloud_inventory(agents),
        scan_sources=scan_sources,
        scan_id=str(uuid.uuid4()),
    )
    freshness = local_data_freshness.freshness_snapshot(offline)
    report.vuln_data_freshness = freshness.to_dict() if freshness is not None else None
    attach_passive_mcp_audit(report)
    return report
