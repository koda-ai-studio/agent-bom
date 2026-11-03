"""Tenant-bound dashboard and finding-context reads."""

from collections import Counter
from functools import partial
from typing import cast

import anyio
from fastapi import APIRouter, Request

from agent_bom.api.current_graph import refuse_unpinned_read_while_seeding
from agent_bom.api.finding_snapshot_read import current_findings_snapshot
from agent_bom.api.models import ScanJob
from agent_bom.api.read_models import documented
from agent_bom.api.read_models.finding_context import FindingContextResponse
from agent_bom.api.scan_dashboard_view import dashboard_job
from agent_bom.api.scan_request_context import _load_job_for_request
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.evidence.finding_context import CONTEXTS, finding_context

router = APIRouter()


@router.get("/scan/{job_id}/dashboard", response_model=ScanJob, tags=["scan"])
async def get_scan_dashboard(request: Request, job_id: str) -> ScanJob:
    """Scan display projection; large AST lists are linked for paged retrieval.

    Original evidence and non-JSON documents remain at GET /v1/scan/{job_id}?view=full.
    Projection uses the same tenant lookup and redaction as the full read.
    """
    job = await _load_job_for_request(request, job_id)
    return cast(ScanJob, await anyio.to_thread.run_sync(partial(dashboard_job, job)))


def _context_row(row: dict) -> dict:
    severity = str(row.get("severity") or "unknown").lower()
    return {
        "path_context": finding_context(row),
        "severity": severity if severity in {"critical", "high", "medium", "low", "info"} else "unknown",
    }


def _context_counts(request: Request) -> dict:
    snapshot = current_findings_snapshot(request, project_graph_reachability=False, row_projection=_context_row)
    counts: dict[str, Counter[str]] = {key: Counter() for key in CONTEXTS}
    for row in snapshot["findings"]:
        counts[row["path_context"]][row["severity"]] += 1
    return {
        "schema_version": "1",
        "basis": "current open finding occurrences; default read window",
        "contexts": [{"context": key, "total": sum(value.values()), "severity": dict(value)} for key, value in counts.items()],
        "count": snapshot["count"],
        "approximate": snapshot["completeness"]["status"] != "complete" or bool(snapshot["warnings"]),
        "warnings": snapshot["warnings"],
    }


@router.get("/findings/context-summary", **documented(FindingContextResponse), tags=["scan"])
async def get_finding_contexts(request: Request) -> dict:
    """Path-derived occurrence counts; no severity, suppression or grade changes.

    Unclassified includes missing paths and is not evidence of production use.
    Bounds and unavailable evidence are reported explicitly.
    """
    refuse_unpinned_read_while_seeding("", require_request_tenant_id(request))
    return cast(dict, await anyio.to_thread.run_sync(partial(_context_counts, request)))
