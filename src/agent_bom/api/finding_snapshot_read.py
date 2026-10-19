"""Current canonical finding snapshots and issue severity aggregates."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import Request

from agent_bom.api.finding_list_helpers import _DEFAULT_FINDING_STATUS, _normalize_finding_sort
from agent_bom.api.finding_page_read import _list_finding_groups_impl, _list_findings_view_impl
from agent_bom.api.finding_read_context import finding_read_snapshot
from agent_bom.api.finding_snapshot_metadata import snapshot_envelope
from agent_bom.api.findings_current import _finding_snapshot_jobs, current_scan_jobs
from agent_bom.api.scan_finding_read import _completed_jobs_for_tenant as _completed_jobs_for_tenant
from agent_bom.api.scan_request_context import _tenant_id


def issue_severity_counts(request: Request) -> dict[str, Any]:
    """Open issue-group severity counts for the findings page default query.

    Nav badges and the overview read this so their numbers equal what the
    grouped ``/v1/findings`` view shows with no filters applied: the same
    tenant, default read window, open status and canonical issue grouping.
    """
    page = _list_finding_groups_impl(
        request,
        None,
        None,
        None,
        _normalize_finding_sort("severity"),
        1,
        0,
        None,
        True,
        include_facets=True,
    )
    severity = (page.get("facets") or {}).get("severity") or {}
    counts: dict[str, Any] = {key: int(severity.get(key) or 0) for key in ("critical", "high", "medium", "low")}
    counts["unrated"] = int(severity.get("info") or 0) + int(severity.get("unknown") or 0)
    counts["total"] = int(page.get("total") or 0)
    counts["approximate"] = bool(page.get("total_approximate"))
    counts["window"] = page.get("window")
    counts["basis"] = "issue_groups"
    return counts


@finding_read_snapshot
def current_findings_snapshot(
    request: Request,
    *,
    max_findings: int = 50_000,
    q: str | None = None,
    severity: str | None = None,
    scan_id: str | None = None,
    provider: str | None = None,
    account: str | None = None,
    environment: str | None = None,
    domain: str | None = None,
    window_days: int | None = None,
    status: str = _DEFAULT_FINDING_STATUS,
    finding_class: str | None = None,
    kev: bool | None = None,
    framework: str | None = None,
    control: str | None = None,
    owner: str | None = None,
    sla: str | None = None,
    reachability: str | None = None,
    triage: str | None = None,
    project_graph_reachability: bool = True,
    row_projection: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    lane: str | None = None,
) -> dict[str, Any]:
    """Collect the canonical current finding queue for an internal consumer.

    Uses the same merged scan + current-ingest keyset stream as GET /v1/findings.
    A bound hit is explicit partial evidence, never a complete snapshot.
    """
    rows: list[dict[str, Any]] = []
    cursor: str | None = None
    first_total: int | None = None
    first_metadata: dict[str, Any] | None = None
    warnings: list[str] = []
    while len(rows) < max_findings:
        page = _list_findings_view_impl(
            request,
            q=q,
            severity=severity,
            scan_id=scan_id,
            sort="effective_reach",
            limit=min(1000, max_findings - len(rows)),
            offset=0,
            cursor=cursor,
            approximate_total=cursor is not None,
            provider=provider,
            account=account,
            environment=environment,
            domain=domain,
            window_days=window_days,
            status=status,
            finding_class=finding_class,
            kev=kev,
            framework=framework,
            control=control,
            owner=owner,
            sla=sla,
            reachability=reachability,
            triage=triage,
            project_graph_reachability=project_graph_reachability or reachability is not None,
            redact_page=row_projection is None,
            lane=lane,
        )
        if first_metadata is None:
            first_metadata = page.get("count_metadata") if isinstance(page.get("count_metadata"), dict) else {}
            first_total = page.get("total") if isinstance(page.get("total"), int) else None
        page_rows = page.get("findings")
        if isinstance(page_rows, list):
            rows.extend((row_projection(row) if row_projection else row) for row in page_rows if isinstance(row, dict))
        warnings.extend(str(item) for item in page.get("warnings", []) if str(item))
        cursor = str(page.get("next_cursor") or "") or None
        if not cursor:
            break

    return _snapshot_response(request, rows, scan_id, first_total, first_metadata, cursor, max_findings, warnings)


def _snapshot_response(
    request: Request,
    rows: list[dict[str, Any]],
    scan_id: str | None,
    first_total: int | None,
    first_metadata: dict[str, Any] | None,
    cursor: str | None,
    max_findings: int,
    warnings: list[str],
) -> dict[str, Any]:
    """Attach current-job coverage to the bounded finding stream."""
    tenant_id = _tenant_id(request)
    retained_jobs = _completed_jobs_for_tenant(tenant_id)
    jobs = (
        current_scan_jobs(retained_jobs, since=None, scan_id=scan_id)
        if scan_id
        else _finding_snapshot_jobs(retained_jobs, since=None, require_authoritative_evidence=True)[0]
    )
    return snapshot_envelope(
        tenant_id=tenant_id,
        rows=rows,
        jobs=jobs,
        first_total=first_total,
        first_metadata=first_metadata,
        cursor=cursor,
        max_findings=max_findings,
        warnings=warnings,
    )
