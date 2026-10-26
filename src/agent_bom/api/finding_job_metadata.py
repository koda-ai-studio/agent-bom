"""Pure scan authority, scope and history semantics shared by writers and readers."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict

from agent_bom.api.models import JobStatus
from agent_bom.evidence.finding_observation import ReconfirmationReason

HistoryKey = tuple[str, str, str, str]


class FindingHistoryJob(BaseModel):
    """Only selection metadata; never an inventory or a finding report."""

    model_config = ConfigDict(strict=True, extra="forbid")
    job_id: str
    tenant_id: str
    status: JobStatus
    created_at: str
    completed_at: str | None
    child_job_ids: list[str]
    result: dict[str, Any] | None
    scope_key: str
    authority_key: tuple[str, str, str]
    authoritative: bool
    incomplete_reasons: list[str]
    scan_aliases: list[str]


class _ScanJobLike(Protocol):
    """Structural contract for the scan-job rows this fold reads.

    Kept as a Protocol (rather than importing ``ScanJob``) so the fold stays
    decoupled from the concrete store row and accepts any object exposing the
    same surface. ``ScanJob`` satisfies it structurally.
    """

    job_id: str
    status: JobStatus
    result: dict[str, Any] | None
    created_at: str
    completed_at: str | None
    child_job_ids: list[str]


_SCAN_TARGET_FIELDS = (
    "inventory",
    "images",
    "k8s",
    "k8s_namespace",
    "tf_dirs",
    "gha_path",
    "repo_url",
    "agent_projects",
    "jupyter_dirs",
    "sbom",
    "external_scan",
    "vex",
    "connectors",
    "filesystem_paths",
    "dynamic_discovery",
    "dynamic_max_depth",
    "discover_host",
    "scope_agents",
    "scope_servers",
    "exclude_agents",
    "exclude_servers",
    "dry_run",
    "no_scan",
)


def _normalized_evidence_timestamp(*values: Any) -> str:
    """Return the first valid timestamp in a UTC-sortable representation."""
    for value in values:
        raw = str(value or "").strip()
        if not raw:
            continue
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat()
    return ""


def scan_evidence_authority_key(job: _ScanJobLike) -> tuple[str, str, str]:
    """Deterministic newest-wins key for one completed scan snapshot.

    The stores do not yet persist one shared commit sequence. If evidence and
    completion timestamps are exactly equal, ``job_id`` is therefore a stable
    backend-independent tie-break, not a claim about commit chronology.
    """
    if isinstance(job, FindingHistoryJob):
        return job.authority_key
    raw_result = getattr(job, "result", None)
    result: dict[str, Any] = raw_result if isinstance(raw_result, dict) else {}
    raw_scan_run = result.get("scan_run")
    scan_run: dict[str, Any] = raw_scan_run if isinstance(raw_scan_run, dict) else {}
    completed_at = _normalized_evidence_timestamp(
        getattr(job, "completed_at", None),
        getattr(job, "created_at", None),
    )
    evidence_at = _normalized_evidence_timestamp(
        result.get("generated_at"),
        result.get("scan_timestamp"),
        scan_run.get("generated_at"),
        completed_at,
    )
    return evidence_at, completed_at, str(getattr(job, "job_id", ""))


def scan_scope_key(job: _ScanJobLike) -> str:
    """Canonical target scope whose newer successful scan replaces the older.

    Result ordering cannot express replacement semantics: an empty successful
    scan has no finding identity to overwrite.  The request's target-bearing
    fields are therefore the durable scope.  Execution/enrichment/output flags
    are intentionally excluded because they do not identify a different asset
    estate.  Legacy/default jobs fall back to their reported scan-source set.
    """
    if isinstance(job, FindingHistoryJob):
        return job.scope_key
    from agent_bom.evidence.push_scope import pushed_scope_key

    raw_result = getattr(job, "result", None)
    result = raw_result if isinstance(raw_result, dict) else {}
    push_scope = pushed_scope_key(job, result)
    if push_scope is not None:
        return push_scope
    request = getattr(job, "request", None)
    if request is not None and hasattr(request, "model_dump"):
        raw_request = request.model_dump(mode="json")
    elif isinstance(request, dict):
        raw_request = request
    else:
        raw_request = {}

    target: dict[str, Any] = {}
    for field in _SCAN_TARGET_FIELDS:
        if field == "dynamic_max_depth" and not raw_request.get("dynamic_discovery"):
            continue
        value = raw_request.get(field)
        if value in (None, "", False, [], {}):
            continue
        if isinstance(value, list):
            value = sorted(str(item) for item in value)
        target[field] = value
    explicit_target = getattr(job, "target", None)
    if isinstance(explicit_target, dict) and explicit_target:
        target["job_target"] = explicit_target
    source_id = str(getattr(job, "source_id", None) or "").strip()
    if source_id:
        target["source_id"] = source_id
    if target:
        return "request:" + json.dumps(target, sort_keys=True, separators=(",", ":"), default=str)

    raw_result = getattr(job, "result", None)
    result = raw_result if isinstance(raw_result, dict) else {}
    explicit = str(result.get("scan_scope") or result.get("source_scope") or "").strip()
    if explicit:
        return f"explicit:{explicit}"
    sources = sorted({str(item).strip() for item in result.get("scan_sources", []) or [] if str(item).strip()})
    return "sources:" + json.dumps(sources or ["local-agents"], separators=(",", ":"))


def _job_matches_scan_id(job: _ScanJobLike, scan_id: str) -> bool:
    if str(getattr(job, "job_id", "")) == scan_id:
        return True
    if isinstance(job, FindingHistoryJob):
        return scan_id in job.scan_aliases
    raw_result = getattr(job, "result", None)
    result: dict[str, Any] = raw_result if isinstance(raw_result, dict) else {}
    raw_scan_run = result.get("scan_run")
    scan_run: dict[str, Any] = raw_scan_run if isinstance(raw_scan_run, dict) else {}
    return scan_id in {str(result.get("scan_id") or ""), str(scan_run.get("scan_id") or "")}


def job_has_authoritative_scan_evidence(job: _ScanJobLike) -> bool:
    """Return whether a completed job represents an executed scan.

    Request validation and inventory-only jobs may finish successfully, but
    ``scan_skipped``, ``dry_run``, and ``no_scan`` cannot prove that a
    detective control operated. Check both request and result because older
    persisted jobs did not consistently copy execution flags into the result.
    """
    if isinstance(job, FindingHistoryJob):
        return job.authoritative
    raw_result = getattr(job, "result", None)
    result: dict[str, Any] = raw_result if isinstance(raw_result, dict) else {}
    if any(bool(result.get(field)) for field in ("scan_skipped", "dry_run", "no_scan")):
        return False
    raw_scan_run = result.get("scan_run")
    scan_run: dict[str, Any] = raw_scan_run if isinstance(raw_scan_run, dict) else {}
    if str(scan_run.get("outcome") or "").strip().casefold() == "failed":
        return False

    request = getattr(job, "request", None)
    if request is not None and hasattr(request, "model_dump"):
        raw_request = request.model_dump(mode="json")
    elif isinstance(request, dict):
        raw_request = request
    else:
        raw_request = {}
    return not any(bool(raw_request.get(field)) for field in ("dry_run", "no_scan"))


def _advisory_data_warning(issue: dict[str, Any]) -> bool:
    return issue.get("source") == "vulnerability-data" and issue.get("code") == "scanner_warning"


def scan_collection_incomplete_reasons(job: _ScanJobLike) -> list[str]:
    """Read explicit coverage receipts; absent legacy metadata proves nothing."""
    if isinstance(job, FindingHistoryJob):
        return job.incomplete_reasons
    result = job.result or {}
    raw = result.get("scan_run")
    run = raw if isinstance(raw, dict) else {}
    reasons: set[str] = set()
    outcome = run.get("outcome")
    raw_issues = run.get("issues")
    issues = [issue for issue in raw_issues if isinstance(issue, dict)] if isinstance(raw_issues, list) else []
    inventory_issues = [issue for issue in issues if not _advisory_data_warning(issue)]
    # Stale advisory data leaves what was collected intact, so it must not keep prior inventory current.
    if outcome == "failed" or (outcome == "partial" and (inventory_issues or not issues)):
        reasons.add(f"scan_{outcome}")
    if any(result.get(key) is True for key in ("scan_skipped", "dry_run", "no_scan")):
        reasons.add(ReconfirmationReason.SCAN_NOT_EXECUTED.value)
    scopes = run.get("scopes")
    for scope in scopes if isinstance(scopes, list) else []:
        if not isinstance(scope, dict) or scope.get("requested") is not True:
            continue
        status = scope.get("status")
        if isinstance(status, str) and status in {"partial", "permission_denied", "unavailable", "unsupported", "skipped"}:
            reasons.add(f"scope_{status}")
    if any(issue.get("affects_coverage") is True for issue in inventory_issues):
        reasons.add(ReconfirmationReason.COVERAGE_ISSUE.value)
    incomplete = run.get("incomplete_scope_count")
    if isinstance(incomplete, int) and not isinstance(incomplete, bool) and incomplete > 0:
        reasons.add(ReconfirmationReason.SCOPE_INCOMPLETE.value)
    return sorted(reasons)


def _retained_finding_key(job: _ScanJobLike, row: dict[str, Any], *, scope: str | None = None) -> tuple[str, str, str, str] | None:
    """Bind history to an explicit canonical occurrence, never a display fallback."""
    identity = row.get("canonical_id")
    if not isinstance(identity, str) or not identity.strip():
        return None
    asset = row.get("asset")
    environment = row.get("environment") or (asset.get("environment") if isinstance(asset, dict) else None) or ""
    return str(getattr(job, "tenant_id", "default")), scope if scope is not None else scan_scope_key(job), identity, str(environment)


def _merge_retained_history_row(history: dict[HistoryKey, dict[str, Any]], key: HistoryKey, row: dict[str, Any]) -> None:
    from agent_bom.graph.sla import merge_finding_sla

    previous = history.get(key, {})
    dates = [value for value in (_normalized_evidence_timestamp(row.get("first_seen")), previous.get("first_seen")) if value]
    first_seen = min(dates) if dates else None
    # A recorded assignment is useful even when its observation date
    # is unavailable; missing dates must not discard manual policy.
    history[key] = merge_finding_sla(row, previous, first_seen=first_seen or "")
    history[key]["first_seen"] = first_seen
