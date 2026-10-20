"""Where ``context_graph`` reads its agents from: the persisted snapshot, or live discovery on request.

The tenant's persisted scan snapshot is the default. Live discovery reads the
MCP server host's own agent configurations, a different estate, so it runs only
when the caller passes ``live=True`` or a ``config_path`` to scan.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from agent_bom.mcp_errors import CODE_NOT_FOUND_AGENTS, CODE_NOT_FOUND_RESOURCE, mcp_error_json
from agent_bom.mcp_tenant import resolve_mcp_tool_tenant_id
from agent_bom.mcp_tools.rest_parity import api_reads, api_unavailable

PERSISTED = "persisted_snapshot"
LIVE = "live_discovery"


@dataclass(frozen=True, slots=True)
class ContextReport:
    agents: list[dict[str, Any]]
    blast_radius: list[dict[str, Any]]
    source: str
    scope: dict[str, Any]


async def persisted_context_report(tenant_id: str, scan_id: str | None) -> ContextReport | str:
    """The tenant's persisted agents and blast radius, or an MCP error naming the gap."""
    reads = api_reads()
    if reads is None:
        return api_unavailable()
    tenant_id = resolve_mcp_tool_tenant_id(tenant_id)
    report = await asyncio.to_thread(reads.persisted_scan_report, tenant_id, scan_id)
    if not report["available"]:
        message = (
            f"No persisted scan '{scan_id}' for this tenant; pass live=true to discover this host's agents instead."
            if scan_id
            else "No persisted scan snapshot for this tenant; run a scan into the control plane or pass live=true."
        )
        return mcp_error_json(CODE_NOT_FOUND_RESOURCE, message, details={"tenant_id": tenant_id, "scan_id": scan_id})
    if not report["agents"]:
        return mcp_error_json(CODE_NOT_FOUND_AGENTS, "The persisted snapshot holds no agents.", details={"tenant_id": tenant_id})
    scope = {"tenant_id": tenant_id, "scan_id": scan_id, "scan_ids": report["scan_ids"]}
    return ContextReport(report["agents"], report["blast_radius"], PERSISTED, scope)


async def live_context_report(config_path: str | None, run_scan_pipeline: Any) -> ContextReport | str:
    """Discover and scan this host's agent configurations, labelled as that narrower scope."""
    from agent_bom.models import AIBOMReport
    from agent_bom.output import to_json

    agents, blast_radii, _warnings, scan_sources = await run_scan_pipeline(config_path)
    if not agents:
        return mcp_error_json(CODE_NOT_FOUND_AGENTS, "No agents discovered in the current scan scope.")
    report_json = to_json(AIBOMReport(agents=agents, blast_radii=blast_radii, scan_sources=scan_sources))
    scope = {"tenant_id": None, "scan_id": None, "basis": "MCP client configurations visible to this MCP server process"}
    return ContextReport(report_json["agents"], report_json.get("blast_radius", []), LIVE, scope)
