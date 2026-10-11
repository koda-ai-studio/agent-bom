"""Canonical current-state fold for scan-produced findings.

The findings list and executive count surfaces share this module so their
default time-window, parent-job exclusion, and cross-job replacement semantics
cannot drift independently.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from typing import Any

from agent_bom.api.finding_job_metadata import (
    HistoryKey as HistoryKey,
)
from agent_bom.api.finding_job_metadata import (
    _job_matches_scan_id as _job_matches_scan_id,
)
from agent_bom.api.finding_job_metadata import (
    _merge_retained_history_row as _merge_retained_history_row,
)
from agent_bom.api.finding_job_metadata import (
    _normalized_evidence_timestamp as _normalized_evidence_timestamp,
)
from agent_bom.api.finding_job_metadata import (
    _retained_finding_key as _retained_finding_key,
)
from agent_bom.api.finding_job_metadata import (
    _ScanJobLike as _ScanJobLike,
)
from agent_bom.api.finding_job_metadata import (
    job_has_authoritative_scan_evidence as job_has_authoritative_scan_evidence,
)
from agent_bom.api.finding_job_metadata import (
    scan_collection_incomplete_reasons as scan_collection_incomplete_reasons,
)
from agent_bom.api.finding_job_metadata import (
    scan_evidence_authority_key as scan_evidence_authority_key,
)
from agent_bom.api.finding_job_metadata import (
    scan_scope_key as scan_scope_key,
)
from agent_bom.api.models import JobStatus
from agent_bom.evidence.finding_observation import FindingObservationStatus


def job_in_window(job: _ScanJobLike, since: str | None) -> bool:
    """Return whether a job's completion timestamp is inside ``since``."""
    if since is None:
        return True
    stamp = getattr(job, "completed_at", None) or getattr(job, "created_at", None)
    try:
        observed = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
        cutoff = datetime.fromisoformat(since.replace("Z", "+00:00"))
        if observed.tzinfo is None:
            observed = observed.replace(tzinfo=timezone.utc)
        if cutoff.tzinfo is None:
            cutoff = cutoff.replace(tzinfo=timezone.utc)
        return observed >= cutoff
    except (TypeError, ValueError):
        return False


def finding_identity(finding: dict[str, Any]) -> str:
    """Stable identity used to collapse a finding across scan jobs."""
    raw_id = finding.get("id")
    if raw_id:
        return str(raw_id)
    vuln_id = finding.get("vulnerability_id") or finding.get("cve_id") or finding.get("title") or ""
    raw_asset = finding.get("asset")
    asset = raw_asset if isinstance(raw_asset, dict) else {}
    package = finding.get("package") or finding.get("package_name") or asset.get("name", "")
    return f"{vuln_id}:{package}"


def scan_only_findings(
    rows: Iterable[dict[str, Any]], tenant_id: str, *, hub: Any = None, scan_id: str | None = None, origin: str | None = "bulk_ingest"
) -> list[dict[str, Any]]:
    """Exclude observations already represented by the hub's current lifecycle.

    Canonical finding IDs identify occurrences, including their asset scope;
    CVE or package names alone never establish equivalence. Once that identity
    is managed by the hub, its lifecycle status and enrichment are authoritative.
    Reconcile BEFORE severity/status filters so a resolved hub occurrence cannot
    reappear as an open scan observation. Lookups are bounded to resident scans.
    """
    from agent_bom.api.finding_lifecycle import resolve_canonical_id

    retained = list(rows)
    if not retained:
        return retained
    if hub is None:
        from agent_bom.api.compliance_hub_store import get_compliance_hub_store

        hub = get_compliance_hub_store()
    lookup = getattr(hub, "lookup_current_ids", None)
    if not callable(lookup):
        return retained
    keys = [resolve_canonical_id(row) for row in retained]
    owned = lookup(tenant_id, keys, scan_id=scan_id, origin=origin)
    return [row for row, key in zip(retained, keys) if key not in owned]


def current_scan_jobs(
    jobs: Iterable[_ScanJobLike],
    *,
    since: str | None,
    scan_id: str | None,
    require_authoritative_evidence: bool = False,
) -> list[_ScanJobLike]:
    """Select the newest successful leaf snapshot for every target scope.

    A newer empty result remains selected and thereby retires the older scope's
    absent findings.  Stable evidence-time/job-id authority makes the result
    independent of InMemory, SQLite, or Postgres return order.
    """
    eligible = [
        job
        for job in jobs
        if getattr(job, "status", None) == JobStatus.DONE
        and isinstance(getattr(job, "result", None), dict)
        and job_in_window(job, since)
        and (not require_authoritative_evidence or job_has_authoritative_scan_evidence(job))
    ]
    if scan_id:
        selected = [job for job in eligible if _job_matches_scan_id(job, scan_id)]
        return sorted(selected, key=scan_evidence_authority_key)

    current: dict[str, _ScanJobLike] = {}
    for job in eligible:
        if getattr(job, "child_job_ids", None):
            continue
        scope = scan_scope_key(job)
        existing = current.get(scope)
        if existing is None or scan_evidence_authority_key(job) > scan_evidence_authority_key(existing):
            current[scope] = job
    return sorted(current.values(), key=lambda job: (scan_evidence_authority_key(job), scan_scope_key(job)))


def current_scan_findings(
    jobs: Iterable[_ScanJobLike],
    *,
    since: str | None,
    scan_id: str | None,
    iter_findings: Callable[[Any], list[dict[str, Any]]],
    require_authoritative_evidence: bool = False,
    history_lookup: Callable[[set[HistoryKey], bool], dict[HistoryKey, dict[str, Any]]] | None = None,
) -> list[dict[str, Any]]:
    """Return the latest current row per identity across eligible scan jobs.

    Parent aggregation jobs are excluded from the unscoped view because their
    child jobs already own the evidence. A direct ``scan_id`` query retains the
    selected job's rows verbatim. Callers asserting that a scan operated may
    require executed evidence, excluding skipped/dry-run/failed outcomes.
    """
    retained_jobs = list(jobs)
    selected_jobs, attempts = _finding_snapshot_jobs(
        retained_jobs, since=since, scan_id=scan_id, require_authoritative_evidence=require_authoritative_evidence
    )
    deduped: dict[tuple[str, str], tuple[tuple[str, str, str], dict[str, Any], _ScanJobLike]] = {}
    for job in selected_jobs:
        authority = scan_evidence_authority_key(job)
        for row in iter_findings(job):
            identity = (str(getattr(job, "tenant_id", "default")), finding_identity(row))
            existing = deduped.get(identity)
            if existing is None or authority > existing[0]:
                deduped[identity] = (authority, row, job)
    if scan_id:
        return [deduped[key][1] for key in sorted(deduped)]

    # Membership retains prior observations only across explicitly incomplete
    # attempts. History can supply dates only for those surviving identities.
    selected = [deduped[key] for key in sorted(deduped)]
    # One scope per job, not per row: deriving it re-serializes the request.
    scopes = {id(job): scan_scope_key(job) for _, _, job in selected}
    wanted = {key for _, row, job in selected if (key := _retained_finding_key(job, row, scope=scopes[id(job)])) is not None}
    history = (
        history_lookup(wanted, require_authoritative_evidence)
        if history_lookup is not None
        else _retained_finding_history(retained_jobs, wanted, require_authoritative_evidence=require_authoritative_evidence)
    )
    from agent_bom.graph.sla import merge_finding_sla

    rows = []
    for _, row, job in selected:
        row = dict(row)
        row.pop("reconfirmation", None)
        row["observation_status"] = FindingObservationStatus.OBSERVED.value
        attempt, reasons = attempts[(str(getattr(job, "tenant_id", "default")), scopes[id(job)])]
        if attempt.job_id != job.job_id and reasons:
            row["observation_status"] = FindingObservationStatus.UNRECONFIRMED.value
            row["reconfirmation"] = {
                "scan_id": attempt.job_id,
                "attempted_at": _normalized_evidence_timestamp(attempt.completed_at, attempt.created_at) or None,
                "reason_codes": reasons,
            }
        key = _retained_finding_key(job, row, scope=scopes[id(job)])
        previous = history.get(key) if key is not None else None
        if previous:
            dates = [value for value in (_normalized_evidence_timestamp(row.get("first_seen")), previous.get("first_seen")) if value]
            first_seen = min(dates) if dates else None
            row = merge_finding_sla(row, previous, first_seen=first_seen or "")
            row["first_seen"] = first_seen
        rows.append(row)
    return rows


def _tenant_scope(job: _ScanJobLike) -> tuple[str, str]:
    return str(getattr(job, "tenant_id", "default")), scan_scope_key(job)


def _finding_snapshot_jobs(
    jobs: Iterable[_ScanJobLike], *, since: str | None, require_authoritative_evidence: bool = False, scan_id: str | None = None
) -> tuple[list[_ScanJobLike], dict[tuple[str, str], tuple[_ScanJobLike, list[str]]]]:
    """Retain the last replacement plus subsequent incomplete observations.

    Legacy snapshots without explicit incompleteness keep their existing
    replacement behavior. This compatibility rule is not a coverage receipt
    and cannot establish remediation verification. Selection uses resident
    tenant history within the requested window; it performs no extra reads.
    """
    if scan_id:
        return current_scan_jobs(jobs, since=since, scan_id=scan_id, require_authoritative_evidence=require_authoritative_evidence), {}
    selected: dict[tuple[str, str], list[_ScanJobLike]] = {}
    attempts: dict[tuple[str, str], tuple[_ScanJobLike, list[str]]] = {}
    for job in sorted(jobs, key=scan_evidence_authority_key):
        if (
            job.status != JobStatus.DONE
            or not isinstance(job.result, dict)
            or getattr(job, "child_job_ids", None)
            or not job_in_window(job, since)
        ):
            continue
        reasons = scan_collection_incomplete_reasons(job)
        executed = not require_authoritative_evidence or job_has_authoritative_scan_evidence(job)
        if not executed and not reasons:
            continue
        scope = _tenant_scope(job)
        attempts[scope] = (job, reasons)
        if not reasons:
            selected[scope] = []
        if executed:
            selected.setdefault(scope, []).append(job)
    return [job for group in selected.values() for job in group], attempts


def _retained_finding_history(
    jobs: list[_ScanJobLike],
    wanted: set[tuple[str, str, str, str]],
    *,
    require_authoritative_evidence: bool,
) -> dict[tuple[str, str, str, str], dict[str, Any]]:
    """Fold metadata from the already loaded tenant history, without enrichment.

    Retention/deletion limits the earliest supported observation. The query's
    display window does not restart it. Legacy projections without an explicit
    canonical finding identity cannot establish this association.
    """
    history: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    if not wanted:
        return history
    scopes = {(key[0], key[1]) for key in wanted}
    for job in sorted(jobs, key=scan_evidence_authority_key):
        scope = scan_scope_key(job)
        if (
            getattr(job, "status", None) != JobStatus.DONE
            or getattr(job, "child_job_ids", None)
            or not isinstance(job.result, dict)
            or (str(getattr(job, "tenant_id", "default")), scope) not in scopes
            or (require_authoritative_evidence and not job_has_authoritative_scan_evidence(job))
        ):
            continue
        for row in job.result.get("findings", []) or []:
            if not isinstance(row, dict):
                continue
            key = _retained_finding_key(job, row, scope=scope)
            if key is None or key not in wanted:
                continue
            _merge_retained_history_row(history, key, row)
    return history


def latest_current_scan_job(
    jobs: Iterable[_ScanJobLike],
    *,
    require_authoritative_evidence: bool = False,
) -> _ScanJobLike | None:
    """Return the newest successful current scan, optionally requiring execution."""
    current = current_scan_jobs(
        jobs,
        since=None,
        scan_id=None,
        require_authoritative_evidence=require_authoritative_evidence,
    )
    return max(current, key=scan_evidence_authority_key) if current else None


__all__ = [
    "current_scan_findings",
    "current_scan_jobs",
    "finding_identity",
    "job_has_authoritative_scan_evidence",
    "job_in_window",
    "latest_current_scan_job",
    "scan_evidence_authority_key",
    "scan_scope_key",
]
