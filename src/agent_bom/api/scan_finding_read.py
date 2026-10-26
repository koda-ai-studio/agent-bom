"""Scan finding read."""

from __future__ import annotations

import json
from collections.abc import Mapping
from functools import partial
from types import SimpleNamespace
from typing import Any

from agent_bom.api import findings_current, time_window
from agent_bom.api.finding_history_read import current_findings_with_history
from agent_bom.api.finding_read_context import read_once
from agent_bom.api.finding_row_inputs import history_ledger_reads_enabled, scan_row_inputs
from agent_bom.api.finding_scope_filters import _row_matches_scope as _row_matches_scope
from agent_bom.api.finding_walk_cache import reuse_rows
from agent_bom.api.findings_current import current_scan_jobs
from agent_bom.api.models import JobStatus, ScanJob
from agent_bom.api.scan_finding_projection import _iter_scan_findings as _iter_scan_findings
from agent_bom.api.scan_finding_projection import scan_row_sources
from agent_bom.api.stores import _get_exception_store, _get_store
from agent_bom.api.suppression_approval import suppression_active


def _completed_jobs_for_tenant(tenant_id: str) -> list[ScanJob]:
    return read_once(
        ("jobs", tenant_id),
        lambda: [job for job in _get_store().list_all(tenant_id=tenant_id) if job.status == JobStatus.DONE and job.result],
    )


def iter_tenant_scan_spine_findings(
    tenant_id: str,
    *,
    since: str | None = None,
    severity: str | None = None,
    scan_id: str | None = None,
    scope: Mapping[str, str] | None = None,
    status: str = "all",
    sanitize: bool = True,
) -> list[dict[str, Any]]:
    """Current scan-spine findings for a tenant — the same source ``/v1/findings`` shows.

    The scan pipeline never writes the compliance hub, so these live only in the
    in-memory job store. The scheduled findings export unions this with the hub
    stream so a scan-based estate is not silently exported as empty. Bounded by
    the scan-job results already resident in memory (no per-tenant DB scan).
    """
    from agent_bom.api.compliance_hub_store import status_matches
    from agent_bom.api.findings_current import scan_only_findings

    rows = _current_scan_rows(tenant_id, since, scan_id)
    rows = scan_only_findings(rows, tenant_id, scan_id=scan_id)
    if severity:
        normalized = severity.lower()
        rows = [item for item in rows if str(item.get("severity", "")).lower() == normalized]
    rows = [item for item in rows if status_matches(item, status)]
    if scope:
        rows = [item for item in rows if _row_matches_scope(item, dict(scope))]
    if not sanitize:
        return rows
    from agent_bom.finding_scope import safe_finding_response_payload

    return [safe_finding_response_payload(row) for row in rows]


def persisted_finding_evidence(
    *,
    tenant_id: str,
    cve_id: str,
    scan_id: str | None = None,
) -> dict[str, Any]:
    """Return one vulnerability from the same persisted finding sources as REST.

    MCP tools call this in-process instead of running a second laptop scan. The
    response distinguishes an empty persisted estate from a process that has no
    persisted scan evidence at all, allowing standalone MCP mode to retain its
    local-scan fallback without mixing the two scopes.
    """
    scan_jobs = _completed_jobs_for_tenant(tenant_id)
    if scan_id:
        scan_jobs = [job for job in scan_jobs if str((job.result or {}).get("scan_id") or job.job_id) == scan_id]
    wanted = cve_id.strip().upper()
    raw_rows = iter_tenant_scan_spine_findings(tenant_id, scan_id=scan_id, status="all", sanitize=False)
    bulk_rows = _bulk_ingested_findings_for_tenant(tenant_id)
    if scan_id:
        bulk_rows = [row for row in bulk_rows if str(row.get("scan_id") or "") == scan_id]
    from agent_bom import finding_scope

    # Sanitizing is the expensive step; only rows that can name the advisory reach it.
    rows = [finding_scope.safe_finding_response_payload(row) for row in [*raw_rows, *bulk_rows] if _may_name_advisory(row, wanted)]
    deduped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in rows:
        key = (
            str(row.get("canonical_id") or row.get("id") or ""),
            str(row.get("cve_id") or row.get("vulnerability_id") or ""),
            str(row.get("package") or row.get("package_name") or ""),
        )
        deduped[key] = row
    matched = [
        row
        for row in deduped.values()
        if str(row.get("cve_id") or row.get("vulnerability_id") or row.get("id") or "").strip().upper() == wanted
    ]
    # An explicit scan scope must never fall through to an unrelated local MCP
    # scan merely because the requested persisted scan is absent.
    source_available = bool(scan_jobs or bulk_rows or scan_id)
    from agent_bom.api.findings_current import scan_collection_incomplete_reasons

    incomplete_reasons = sorted(
        {reason for job in current_scan_jobs(scan_jobs, since=None, scan_id=scan_id) for reason in scan_collection_incomplete_reasons(job)}
    )
    return {
        "available": source_available,
        "source": "persisted_scan_findings",
        "scope": {"tenant_id": tenant_id, "scan_id": scan_id},
        "completeness": {
            "status": "partial" if incomplete_reasons else "complete",
            "basis": "persisted_row_enumeration",
            "reason": (
                "Collection was incomplete; retained earlier findings may be unreconfirmed."
                if incomplete_reasons
                else "Persisted rows were enumerated; this does not establish collection coverage."
            ),
            "reason_codes": incomplete_reasons,
        },
        "findings": matched,
    }


def _may_name_advisory(row: dict[str, Any], wanted: str) -> bool:
    """A superset of the post-sanitization match: sanitizing only removes characters from these ids."""
    return any(wanted in str(row.get(field) or "").upper() for field in ("cve_id", "vulnerability_id", "id"))


def _bulk_ingested_findings_for_tenant(tenant_id: str) -> list[dict[str, Any]]:
    from agent_bom.api.compliance_hub_store import get_compliance_hub_store

    return [item for item in get_compliance_hub_store().list(tenant_id) if isinstance(item, dict) and item.get("origin") == "bulk_ingest"]


def scan_rows_inputs(tenant_id: str, window_since: str | None, job_store: Any) -> tuple[tuple[str, ...], float | None] | None:
    """Fingerprint the fold's non-job inputs; the window enters as the jobs it selects, not the moving cutoff.

    ``None`` (never reuse) while ledger-backed reads are enabled: a history
    backfill writes the ledger without bumping the job revision.
    """
    if history_ledger_reads_enabled():
        return None
    summaries = job_store.list_summary(tenant_id=tenant_id, status=JobStatus.DONE)
    in_window = [str(row.get("job_id")) for row in summaries if findings_current.job_in_window(SimpleNamespace(**row), window_since)]
    return scan_row_inputs(tenant_id, sources=scan_row_sources(tenant_id), window_job_ids=in_window)


def _current_scan_rows(tenant_id: str, window_since: str | None, scan_id: str | None) -> list[dict[str, Any]]:
    def fold() -> list[dict[str, Any]]:
        return current_findings_with_history(
            _get_store(),
            tenant_id,
            window_since,
            scan_id,
            _iter_scan_findings,
            lambda: findings_current.current_scan_findings(
                _completed_jobs_for_tenant(tenant_id),
                since=window_since,
                scan_id=scan_id,
                iter_findings=_cached_scan_findings,
            ),
            fold=findings_current.current_scan_findings,
            select_jobs=findings_current._finding_snapshot_jobs,
        )

    job_store = _get_store()
    inputs = partial(scan_rows_inputs, tenant_id, window_since, job_store)
    return read_once(
        ("current_rows", json.dumps([tenant_id, window_since, scan_id])),
        lambda: reuse_rows(("current_rows", scan_id), tenant_id=tenant_id, job_store=job_store, inputs=inputs, load=fold),
    )


def _cached_scan_findings(job: ScanJob) -> list[dict[str, Any]]:
    key = json.dumps([job.tenant_id, job.job_id, str(job.status), job.completed_at])
    return read_once(("rows", key), lambda: _iter_scan_findings(job))


def current_open_scan_findings(jobs: list[Any]) -> list[dict[str, Any]]:
    """Open, executed-evidence current rows, shared by every block of one aggregate read."""
    from agent_bom.api.compliance_hub_store import status_matches

    since = time_window.window_since_iso(time_window.normalize_window_days(None))
    tenant_id = str(getattr(jobs[0], "tenant_id", "default")) if jobs else "default"
    job_keys = sorted((str(job.job_id), str(job.status), str(job.completed_at)) for job in jobs)

    def load() -> list[dict[str, Any]]:
        rows = findings_current.current_scan_findings(
            jobs, since=since, scan_id=None, iter_findings=_cached_scan_findings, require_authoritative_evidence=True
        )
        # A suppressed finding (operator VEX, accepted exception) is kept as
        # evidence but is not open; ``finding_summary`` excludes it the same way.
        return [
            row
            for row in findings_current.scan_only_findings(rows, tenant_id)
            if status_matches(row, "open") and row.get("suppressed") is not True
        ]

    return read_once(("current_open_rows", json.dumps([tenant_id, since, job_keys])), load)


def suppressed_finding_ids(tenant_id: str) -> frozenset[str]:
    """Finding occurrences an approved exception suppresses now, read from the rows ``/v1/findings`` serves.

    The graph keeps occurrences by finding id; overlaying this set is how a
    graph read applies the one suppression source without a second matcher.
    """
    if not any(suppression_active(exc) for exc in _get_exception_store().list_all(tenant_id=tenant_id)):
        return frozenset()
    rows = iter_tenant_scan_spine_findings(tenant_id, status="all", sanitize=False)
    return frozenset(
        str(value) for row in rows if row.get("suppressed") is True for value in (row.get("id"), row.get("finding_id")) if value
    )
