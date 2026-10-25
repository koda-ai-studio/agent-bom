"""API reads the MCP tools reuse, so a tool and its REST route share one implementation.

MCP modules reach the API through this one facade (see
``agent_bom.mcp_tools.rest_parity``) and only when a tool runs, so MCP-only
installs never import FastAPI.
"""

from __future__ import annotations

from typing import Any

# Starlette's base class, so the current-estate store's refusals are caught with route errors.
from starlette.exceptions import HTTPException

from agent_bom.api.finding_view_filters import _finding_triage_state
from agent_bom.api.findings_current import current_scan_jobs
from agent_bom.api.graph_diff_read import graph_diff_read
from agent_bom.api.graph_estate_changes import graph_estate_changes_read
from agent_bom.api.mcp_blast_reads import blast_holders as blast_holders
from agent_bom.api.mcp_blast_reads import public_holders as public_holders
from agent_bom.api.mcp_blast_reads import stamp_rows as stamp_rows
from agent_bom.api.mcp_context_estate import estate_context_page as estate_context_page
from agent_bom.api.routes.advisory_affected import get_advisory_affected_assets as get_advisory_affected_assets
from agent_bom.api.routes.compliance import get_compliance_by_framework, get_compliance_summary
from agent_bom.api.routes.compliance_routes.common import estate_agent_count
from agent_bom.api.routes.enterprise import build_tenant_triage_state_index
from agent_bom.api.routes.graph_routes._admission import admitted_graph_read, graph_admitted
from agent_bom.api.routes.graph_routes.vendor_paths import get_cross_vendor_attack_paths as get_cross_vendor_attack_paths
from agent_bom.api.routes.operator_advisories import operator_advisory_matches
from agent_bom.api.routes.scan import list_findings
from agent_bom.api.scan_finding_read import _bulk_ingested_findings_for_tenant, _completed_jobs_for_tenant, iter_tenant_scan_spine_findings
from agent_bom.api.stores import _get_operator_advisory_store, operator_advisory_store_configured
from agent_bom.finding_scope import safe_finding_response_payload
from agent_bom.scanners.operator_advisory import OPERATOR_ADVISORY_PROVENANCE, OperatorAdvisory


async def call_read(route_name: str, request: Any, **params: Any) -> Any:
    """Run the named route function as its route does: graph routes keep their snapshot admission."""
    endpoint = globals()[route_name]
    if graph_admitted(endpoint):
        return await admitted_graph_read(endpoint, request, **params)
    return await endpoint(request, **params)


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


def tenant_operator_advisory(tenant_id: str, advisory_id: str) -> dict[str, Any] | None:
    """The tenant's declared advisory (by id or alias) and the matches ``/v1/intel/operator-advisories/{id}/matches`` returns."""
    wanted = advisory_id.strip().upper()
    for row in _get_operator_advisory_store().list(tenant_id):
        declared = OperatorAdvisory.model_validate({k: v for k, v in row.items() if k != "updated_at"})
        if wanted in {identifier.upper() for identifier in declared.identifiers}:
            return {
                "provenance": OPERATOR_ADVISORY_PROVENANCE,
                "source": "tenant_store",
                "advisory": declared.model_dump(mode="json"),
                "matches": operator_advisory_matches(tenant_id, declared.id),
            }
    return None


__all__ = [
    "HTTPException",
    "call_read",
    "current_estate_agent_total",
    "get_advisory_affected_assets",
    "get_compliance_by_framework",
    "get_compliance_summary",
    "graph_diff_read",
    "graph_estate_changes_read",
    "has_completed_scans",
    "list_findings",
    "operator_advisory_store_configured",
    "persisted_finding",
    "persisted_scan_report",
    "tenant_operator_advisory",
    "triage_state",
]
