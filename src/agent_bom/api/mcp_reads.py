"""API reads the MCP tools reuse, so a tool and its REST route share one implementation.

MCP modules reach the API through this one facade (see
``agent_bom.mcp_tools.rest_parity``) and only when a tool runs, so MCP-only
installs never import FastAPI.
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException

from agent_bom.api.finding_view_filters import _finding_triage_state
from agent_bom.api.graph_diff_read import graph_diff_read
from agent_bom.api.graph_estate_changes import graph_estate_changes_read
from agent_bom.api.routes.compliance import get_compliance_by_framework, get_compliance_summary
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


def triage_state(tenant_id: str, row: dict[str, Any]) -> dict[str, Any] | None:
    """The newest active triage/VEX decision matching one finding row."""
    return _finding_triage_state(row, build_tenant_triage_state_index(tenant_id))


__all__ = [
    "HTTPException",
    "get_compliance_by_framework",
    "get_compliance_summary",
    "graph_diff_read",
    "graph_estate_changes_read",
    "has_completed_scans",
    "list_findings",
    "persisted_finding",
    "triage_state",
]
