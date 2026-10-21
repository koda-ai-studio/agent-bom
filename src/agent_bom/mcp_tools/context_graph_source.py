"""Where ``context_graph`` reads its agents from: the persisted snapshot, or live discovery on request.

The tenant's persisted scan snapshot is the default. Live discovery reads the
MCP server host's own agent configurations, a different estate, so it runs only
when the caller passes ``live=True`` or a ``config_path`` to scan.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from agent_bom.graph.completeness import graph_completeness
from agent_bom.mcp_errors import CODE_NOT_FOUND_AGENTS, CODE_NOT_FOUND_RESOURCE, mcp_error_json
from agent_bom.mcp_tenant import resolve_mcp_tool_tenant_id
from agent_bom.mcp_tools.rest_parity import api_reads, api_unavailable

PERSISTED = "persisted_snapshot"
LIVE = "live_discovery"
ESTATE = "current_estate_graph"


@dataclass(frozen=True, slots=True)
class ContextReport:
    agents: list[dict[str, Any]]
    blast_radius: list[dict[str, Any]]
    source: str
    scope: dict[str, Any]
    estate_agents: int | None = None
    page: dict[str, Any] | None = None


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
    estate_agents = None if scan_id else await asyncio.to_thread(reads.current_estate_agent_total, tenant_id)
    return ContextReport(report["agents"], report["blast_radius"], PERSISTED, scope, estate_agents)


async def estate_context_report(tenant_id: str, *, offset: int, limit: int) -> ContextReport | None:
    """One agent page of the tenant's current estate graph, the page ``/v1/graph?entity_types=agent`` serves.

    ``None`` when the API is not installed or the estate graph holds no agents;
    the caller then reads the persisted scan reports.
    """
    reads = api_reads()
    if reads is None:
        return None
    tenant_id = resolve_mcp_tool_tenant_id(tenant_id)
    page = await asyncio.to_thread(reads.estate_context_page, tenant_id, offset=offset, limit=limit)
    if page is None:
        return None
    scope = {"tenant_id": tenant_id, "scan_id": page["scan_id"], "snapshot_created_at": page["created_at"]}
    return ContextReport(page["agents"], page["blast_radius"], ESTATE, scope, page["total"], page)


def _coverage(report: ContextReport, agents_in_view: int) -> dict[str, Any] | None:
    if report.source not in {PERSISTED, ESTATE} or report.estate_agents is None:
        return None
    offset = int((report.page or {}).get("offset") or 0)
    return {
        "agents_in_view": agents_in_view,
        "current_estate_agents": report.estate_agents,
        "covers_current_estate": offset == 0 and agents_in_view >= report.estate_agents,
        "basis": (
            "one agent page of the current estate graph (GET /v1/graph?entity_types=agent)"
            if report.source == ESTATE
            else "persisted scan reports vs the current estate graph (the /v1/posture/counts agents total)"
        ),
        "estate_tools": ["inventory_summary", "exposure_paths", "blast_radius"],
    }


def apply_scope_metadata(result: dict[str, Any], report: ContextReport) -> None:
    """Stamp source, scope, estate coverage, agent pagination and an honest completeness verdict."""
    result.update(source=report.source, scope=report.scope)
    coverage = _coverage(report, int(result["stats"]["agent_count"]))
    if coverage is None:
        return
    result["estate_coverage"] = coverage
    page = report.page or {}
    hop_cut = bool(page.get("hop_truncated") or page.get("depth_limited"))
    if report.page is not None:
        offset, returned = int(page["offset"]), coverage["agents_in_view"]
        has_more = offset + returned < coverage["current_estate_agents"]
        result["pagination"] = {
            "offset": offset,
            "limit": page["limit"],
            "returned": returned,
            "total": coverage["current_estate_agents"],
            "has_more": has_more,
            "next_offset": offset + returned if has_more else None,
        }
    if coverage["covers_current_estate"] and not hop_cut:
        return
    result["path_completeness"] = result["completeness"]
    result["completeness"] = graph_completeness(
        returned=coverage["agents_in_view"],
        total=coverage["current_estate_agents"],
        truncated=True,
        reason=(
            "dependency depth limit reached; deeper transitive packages are not in this context"
            if page.get("depth_limited") and coverage["covers_current_estate"]
            else "context hop limit reached; narrow the page"
            if hop_cut and coverage["covers_current_estate"]
            else "one agent page of the current estate; page with offset/limit"
            if report.source == ESTATE
            else "scan reports hold a subset of the current estate's agents; use inventory_summary or exposure_paths for the estate"
        ),
    )


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
