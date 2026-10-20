"""Estate correlation read API — cross-environment agent matches from scan evidence.

Surfaces the same ``correlate_cross_environment`` matcher the graph builder uses
when emitting ``CORRELATES_WITH`` / ``POSSIBLY_CORRELATES_WITH`` edges, without
requiring a full graph load.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, cast

from fastapi import APIRouter, HTTPException, Query, Request

from agent_bom.api.current_graph import graph_scan_id
from agent_bom.api.findings_current import _finding_snapshot_jobs
from agent_bom.api.models import JobStatus
from agent_bom.api.read_models import documented
from agent_bom.api.read_models.governance_b import EstateCorrelationsResponse
from agent_bom.api.stores import _get_store
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.cross_env_correlation import CorrelationConfidence, correlate_cross_environment
from agent_bom.rbac import require_authenticated_permission

router = APIRouter(dependencies=[cast(Any, require_authenticated_permission("read"))])


def _tenant_id(request: Request) -> str:
    return require_request_tenant_id(request)


CURRENT_ESTATE = "current-estate"


def _done_jobs(tenant_id: str) -> list[Any]:
    return [job for job in _get_store().list_all(tenant_id=tenant_id) if job.status == JobStatus.DONE and job.result]


def _selected_jobs(tenant_id: str, scan_id: str | None) -> tuple[str | None, list[Any]]:
    """``(scan_id label, source jobs)``: the current estate by default, else one job by job or graph snapshot id."""
    jobs = _done_jobs(tenant_id)
    if not scan_id or scan_id == CURRENT_ESTATE or scan_id.startswith(CURRENT_ESTATE + ":"):
        selected, _ = _finding_snapshot_jobs(jobs, since=None, require_authoritative_evidence=False)
        return (CURRENT_ESTATE if selected else None), selected
    match = next((job for job in jobs if job.job_id == scan_id), None) or next((job for job in jobs if graph_scan_id(job) == scan_id), None)
    return (match.job_id, [match]) if match else (None, [])


def _match_payload(match: Any) -> dict[str, Any]:
    payload = asdict(match)
    confidence = payload.pop("confidence", None)
    if isinstance(confidence, CorrelationConfidence):
        payload["confidence"] = confidence.value
    elif hasattr(confidence, "value"):
        payload["confidence"] = confidence.value
    payload["matched_signals"] = list(payload.get("matched_signals") or ())
    return payload


@router.get("/estate/correlations", **documented(EstateCorrelationsResponse), tags=["estate"], deprecated=True)
def get_estate_correlations(
    request: Request,
    scan_id: str | None = Query(
        None,
        description=(
            "Scan job ID or graph snapshot ID. Omitted (or current-estate): the current estate, "
            "the union of every target's current completed scan; source_scan_ids lists them."
        ),
    ),
) -> dict[str, Any]:
    """Return local↔cloud agent correlation matches for a completed scan.

    Soft-deprecated: no UI/CLI/MCP product consumer (#3666 Phase 2).
    """
    tenant_id = _tenant_id(request)
    label, jobs = _selected_jobs(tenant_id, scan_id)
    if not jobs:
        if scan_id and label is None and not scan_id.startswith(CURRENT_ESTATE):
            raise HTTPException(status_code=404, detail=f"Completed scan '{scan_id}' not found")
        return {
            "schema_version": "estate.correlations.v1",
            "tenant_id": tenant_id,
            "scan_id": None,
            "source_scan_ids": [],
            "count": 0,
            "high_confidence_count": 0,
            "low_confidence_count": 0,
            "matches": [],
        }

    agents = [agent for job in jobs for agent in ((job.result or {}).get("agents") or []) if isinstance(agent, dict)]
    result = correlate_cross_environment(agents)
    matches = [_match_payload(match) for match in result.matches]
    high = len(result.by_confidence(CorrelationConfidence.HIGH))
    low = len(result.by_confidence(CorrelationConfidence.LOW))

    return {
        "schema_version": "estate.correlations.v1",
        "tenant_id": tenant_id,
        "scan_id": label,
        "source_scan_ids": [job.job_id for job in jobs],
        "count": len(matches),
        "high_confidence_count": high,
        "low_confidence_count": low,
        "matches": matches,
    }
