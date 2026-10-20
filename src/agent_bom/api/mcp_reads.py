"""API reads the MCP tools reuse, so a tool and its REST route share one implementation.

MCP modules reach the API through this one facade (see
``agent_bom.mcp_tools.rest_parity``) and only when a tool runs, so MCP-only
installs never import FastAPI.
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException

from agent_bom.api.finding_view_filters import _finding_triage_state
from agent_bom.api.findings_current import current_scan_jobs
from agent_bom.api.graph_diff_read import graph_diff_read
from agent_bom.api.graph_estate_changes import graph_estate_changes_read
from agent_bom.api.mcp_blast_reads import blast_holders as blast_holders
from agent_bom.api.mcp_blast_reads import public_holders as public_holders
from agent_bom.api.mcp_blast_reads import stamp_rows as stamp_rows
from agent_bom.api.routes.compliance import get_compliance_by_framework, get_compliance_summary
from agent_bom.api.routes.compliance_routes.common import estate_agent_count
from agent_bom.api.routes.enterprise import build_tenant_triage_state_index
from agent_bom.api.routes.scan import list_findings
from agent_bom.api.scan_finding_read import _bulk_ingested_findings_for_tenant, _completed_jobs_for_tenant, iter_tenant_scan_spine_findings
from agent_bom.finding_scope import safe_finding_response_payload


def has_completed_scans(tenant_id: str) -> bool:
    """Whether the tenant control plane holds any completed scan evidence."""
    return bool(_completed_jobs_for_tenant(tenant_id))


def persisted_finding(tenant_id: str, finding_id: str, scan_id: str | None = None) -> dict[str, Any] | None:
    """One finding row from the same scan spine and bulk-ingest sources ``/v1/findings`` reads."""
    wanted = finding_id.strip()
    rows = iter_tenant_scan_spine_findings(tenant_id, scan_id=scan_id, status="all")
    rows.extend(safe_finding_response_payload(row) for row in _bulk_ingested_findings_for_tenant(tenant_id))
    return next((row for row in rows if wanted in {str(row.get(key) or "") for key in ("id", "finding_id", "canonical_id")}), None)


def persisted_scan_report(tenant_id: str, scan_id: str | None = None) -> dict[str, Any]:
    """The agents and blast radius of the tenant's current scan snapshot (or one scan).

    Uses the same newest-per-target selection as ``/v1/findings``, so a rescanned
    target contributes only its latest result.
    """
    jobs = current_scan_jobs(_completed_jobs_for_tenant(tenant_id), since=None, scan_id=scan_id)
    agents: list[Any] = []
    blast_radius: list[Any] = []
    scan_ids: list[str] = []
    for job in jobs:
        result = job.result or {}
        agents.extend(item for item in result.get("agents") or [] if isinstance(item, dict))
        blast_radius.extend(item for item in result.get("blast_radius") or [] if isinstance(item, dict))
        scan_ids.append(str(result.get("scan_id") or job.job_id))
    return {"available": bool(jobs), "agents": agents, "blast_radius": blast_radius, "scan_ids": sorted(set(scan_ids))}


def current_estate_agent_total(tenant_id: str) -> int | None:
    """Agents in the tenant's current estate graph, the count ``/v1/posture/counts`` reports."""
    total = estate_agent_count(tenant_id)["total"]
    return None if total is None else int(total)


def triage_state(tenant_id: str, row: dict[str, Any]) -> dict[str, Any] | None:
    """The newest active triage/VEX decision matching one finding row."""
    return _finding_triage_state(row, build_tenant_triage_state_index(tenant_id))


__all__ = [
    "HTTPException",
    "current_estate_agent_total",
    "get_compliance_by_framework",
    "get_compliance_summary",
    "graph_diff_read",
    "graph_estate_changes_read",
    "has_completed_scans",
    "list_findings",
    "persisted_finding",
    "persisted_scan_report",
    "triage_state",
]
