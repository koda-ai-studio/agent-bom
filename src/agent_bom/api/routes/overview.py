"""Cross-domain overview aggregation route.

Composes existing per-domain summary logic into a single read-only payload that
powers the unified overview / command-center landing page. No new scan or
ingestion logic lives here — every metric is read from a store or summary
function that another route already exposes:

    * Cloud / CNAPP + Ops + Findings  -> scan-job store (unified findings spine)
    * Runtime                          -> deployment-context signals
    * LLM cost                         -> cost store summary
    * NHI / identity                   -> agent-identity store + fleet store
    * Posture + headline               -> the SAME unified findings spine the
      coverage lanes read, folded with compliance-hub current-state severity
      counts so findings ingested via ``POST /v1/findings/bulk`` move the
      grade/headline (not scan jobs alone)

The exec headline severity counts and risk grade use the exact default-window,
parent-job exclusion, and cross-job replacement semantics of ``/v1/findings``.
The five coverage lanes use the same current, open findings and
preserve overlapping discipline membership. Hub lane aggregation is bounded;
partial counts are explicit lower bounds, never a claim of absent evidence.
Canonicalized blast-radius evidence is included in current scan findings.

Domain tiles (cloud / vuln / code / runtime / ...) remain scan-scoped by
design; the posture, headline and security-discipline lanes aggregate scan + ingested
evidence."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from importlib import import_module
from types import SimpleNamespace
from typing import Any, cast

import anyio.to_thread
from fastapi import APIRouter, Depends, HTTPException, Request

from agent_bom.api.demo_refresh import demo_daily_evidence_dependency
from agent_bom.api.exec_posture import issue_counts_payload, issue_severity_counts
from agent_bom.api.finding_read_context import finding_read_snapshot
from agent_bom.api.models import ExecScoreConfigUpdateRequest, JobStatus
from agent_bom.api.overview_cache import (
    _overview_cache_get,
    _overview_cache_lock,
    _overview_cache_put,
    _overview_fingerprint,
    _overview_inflight,
    _overview_singleflight_timeout,
    _OverviewFlight,
    _scan_aggregate_get,
    _scan_aggregate_put,
)
from agent_bom.api.overview_hub import (
    _current_coverage,
    _hub_coverage_snapshot,
    _hub_failing_frameworks_snapshot,
    _hub_kev_snapshot,
    _hub_severity_snapshot,
    _hub_top_risks,
    _raise_hub_overview_unavailable,
)
from agent_bom.api.overview_projection import (
    _cloud_account_count,
    _cost_snapshot,
    _exec_posture,
    _identity_snapshot,
    _identity_status,
    _posture_snapshot,
    _repo_scan_count,
    _runtime_snapshot,
)
from agent_bom.api.overview_rollup import (
    _ALL_SEVERITY_KEYS,
    _COVERAGE_DOMAINS,
    _COVERAGE_LABELS,
    _cloud_graph_href,
    _combined_severity,
    _empty_severity,
    _exec_estate,
    _fold_findings,
    _graph_drill_href,
    _job_package_count,
    _merge_top_risks,
    _reconciled_exec_counts,
    _rollup_from_blast_radius,
    _rollup_from_summary,
    _tenant_id,
)
from agent_bom.api.read_models import OverviewResponse, documented, governance_b
from agent_bom.api.stores import _get_store
from agent_bom.backpressure import BackpressureRejectedError, adaptive_backpressure
from agent_bom.demo_estate.boot_seed import demo_estate_seeding
from agent_bom.rbac import require_authenticated_permission

router = APIRouter(
    dependencies=[
        Depends(demo_daily_evidence_dependency),
        cast(Any, require_authenticated_permission("read")),
    ]
)


_logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _HubOverviewSnapshot:
    """One revision-consistent view of every hub-derived Overview component."""

    severity: dict[str, int]
    failing_frameworks: set[str]
    kev: int
    top_risks: list[dict[str, Any]]
    revision: int | None
    coverage: tuple[dict[str, dict[str, int]], str] | None = None


_HUB_SNAPSHOT_MAX_ATTEMPTS = 3


def _estate_rollup(jobs: list[Any]) -> dict[str, Any]:
    """Single reconciled rollup over the unified findings spine (#3961/#3962/#3963).

    The exec headline severity counts, the five coverage lanes, the top-risk
    strip, and the risk grade are all built from ONE pass over the same
    ``findings`` stream so a scan-produced non-CVE critical can never be visible
    in one surface and invisible in another. Per completed scan the richest
    evidence available is folded in, in precedence order:

      1. the unified ``findings`` spine (the superset — carries the non-CVE
         findings the pipeline adds beyond ``blast_radius``),
      2. else the CVE-only ``blast_radius`` (legacy / pre-spine results),
      3. else the compact ``summary`` (after hot-cache compaction drops both).

    Findings are deduped by id across re-scans (mirrors the coverage-lane
    dedup). ``compliance_failing`` counts the distinct frameworks with at least
    one critical/high finding — cheap because it is accumulated in this same
    pass, not a second control-by-control evaluation.
    """
    severity = _empty_severity()
    lanes: dict[str, dict[str, int]] = {dom: _empty_severity() for dom in _COVERAGE_DOMAINS}
    lane_counts: dict[str, int] = {dom: 0 for dom in _COVERAGE_DOMAINS}
    seen: set[str] = set()
    failing_frameworks: set[str] = set()
    top_risks: list[dict[str, Any]] = []
    sources: set[str] = set()
    scan_count = 0
    done_count = 0
    failed_count = 0
    running_count = 0
    kev = 0
    credential_exposed = 0
    unique_findings = 0
    unique_packages = 0
    latest_scan_at: str | None = None

    from agent_bom.api import time_window
    from agent_bom.api.findings_current import (
        current_scan_jobs,
        job_has_authoritative_scan_evidence,
        scan_evidence_authority_key,
    )

    # Operational counters describe job history. Evidence-bearing posture below
    # is folded only from the newest successful snapshot per target scope.
    for job in jobs:
        status = getattr(job, "status", None)
        if status == JobStatus.FAILED:
            failed_count += 1
        elif status == JobStatus.RUNNING:
            running_count += 1
        if status != JobStatus.DONE or not isinstance(getattr(job, "result", None), dict):
            continue
        scan_count += 1
        done_count += 1
        if job_has_authoritative_scan_evidence(job):
            completed = scan_evidence_authority_key(job)[1]
            if completed and (latest_scan_at is None or completed > latest_scan_at):
                latest_scan_at = completed

    since = time_window.window_since_iso(time_window.normalize_window_days(None))
    evidence_jobs = current_scan_jobs(
        jobs,
        since=since,
        scan_id=None,
        require_authoritative_evidence=True,
    )
    for job in evidence_jobs:
        result = cast(dict[str, Any], job.result)

        for src in result.get("scan_sources", []) or []:
            if src:
                sources.add(str(src))

        findings = result.get("findings")
        blast_radius = result.get("blast_radius") or []
        if findings:
            added, add_kev, add_cred = _fold_findings(
                cast(list[Any], findings),
                severity=severity,
                lanes=lanes,
                lane_counts=lane_counts,
                seen=seen,
                top_risks=top_risks,
                failing_frameworks=failing_frameworks,
            )
            kev += add_kev
            credential_exposed += add_cred
            unique_findings += added
            unique_packages += _job_package_count(result)
        elif blast_radius:
            # Fallback: no spine on this result — CVE-only blast_radius. Every
            # entry is a dependency CVE, so it folds into the vuln lane.
            partial = _rollup_from_blast_radius(cast(list[dict[str, Any]], blast_radius))
            for key in _ALL_SEVERITY_KEYS:
                severity[key] += partial["severity"][key]
                lanes["vuln"][key] += partial["severity"][key]
            lane_counts["vuln"] += partial["unique_cves"]
            kev += partial["kev"]
            credential_exposed += partial["credential_exposed"]
            unique_findings += partial["unique_cves"]
            top_risks.extend(partial["top_risks"])
            unique_packages += _job_package_count(result)
        else:
            # Fallback: compacted result — only the compact summary survives.
            partial = _rollup_from_summary(result)
            for key in _ALL_SEVERITY_KEYS:
                severity[key] += partial["severity"][key]
                lanes["vuln"][key] += partial["severity"][key]
            lane_counts["vuln"] += partial["unique_cves"]
            unique_findings += partial["unique_cves"]
            unique_packages = max(unique_packages, partial["unique_packages"])

    top_risks.sort(key=lambda r: r["risk_score"], reverse=True)
    coverage = [
        {
            "domain": dom,
            "label": _COVERAGE_LABELS[dom],
            "href": f"/findings?domain={dom}",
            "count": lane_counts[dom],
            "severity": lanes[dom],
        }
        for dom in _COVERAGE_DOMAINS
    ]

    return {
        # All-domain reconciled histogram — the headline + grade basis.
        "severity": severity,
        "coverage": coverage,
        # Vuln-lane specifics for the scan-scoped "Vuln / SCA" domain tile.
        "vuln_severity": lanes["vuln"],
        "unique_cves": lane_counts["vuln"],
        "sources": sorted(sources),
        "scan_count": scan_count,
        "done_count": done_count,
        "failed_count": failed_count,
        "running_count": running_count,
        "kev": kev,
        "credential_exposed": credential_exposed,
        "unique_findings": unique_findings,
        "unique_packages": unique_packages,
        "top_risks": top_risks[:10],
        "latest_scan_at": latest_scan_at,
        "compliance_failing": len(failing_frameworks),
        "compliance_failing_frameworks": sorted(failing_frameworks),
    }


def exec_severity_counts(request: Request, jobs: list[Any]) -> dict[str, int]:
    """Reconciled current exec severity counts for ``jobs`` + hub evidence.

    Public entry point shared with ``/v1/posture/counts`` so nav badges and the
    overview headline read one number. Recomputes the estate rollup and hub
    snapshot; a caller that already holds them should use
    ``_reconciled_exec_counts`` directly to avoid a second pass.
    """
    from agent_bom.api.compliance_hub_store import get_compliance_hub_store

    estate = _estate_rollup(jobs)
    hub_snapshot = _capture_hub_overview_snapshot(
        request,
        get_compliance_hub_store(),
        include_details=False,
        require_revision=True,
    )
    return _reconciled_exec_counts(_exec_estate(estate, jobs), hub_snapshot.severity, hub_snapshot.kev)


@router.get("/overview", **documented(OverviewResponse), tags=["overview"])
async def get_overview(request: Request) -> dict[str, Any]:
    """Cross-domain posture snapshot for the unified landing page.

    Read-only. Composes existing stores and summary helpers into one payload
    keyed by domain so the overview page can render a tile per domain plus a
    shared top-risks strip without fanning out to a dozen endpoints.

    The store + DB work (job rollup, hub severity GROUP BY, cost/identity/fleet
    stores) is offloaded off the event loop under the adaptive backpressure
    guard so a burst of overview reads cannot starve ``/health`` (#3963).
    """
    try:
        async with adaptive_backpressure("overview"):
            payload = cast(dict[str, Any], await anyio.to_thread.run_sync(_build_overview, request))
    except BackpressureRejectedError as exc:
        raise HTTPException(
            status_code=429,
            detail=exc.to_dict(),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc
    # Copy rather than mutate: the built payload may be a shared cache entry.
    return {**payload, "demo_estate_seeding": demo_estate_seeding()}


def _capture_hub_overview_snapshot(
    request: Request,
    hub_store: Any,
    *,
    include_details: bool = True,
    require_revision: bool = False,
) -> _HubOverviewSnapshot:
    """Read all hub inputs under one durable tenant revision.

    Each aggregate is independently bounded/indexed, so no cross-backend
    transaction spans the read. The durable revision supplies optimistic
    snapshot isolation instead: every component is captured between two equal
    revision reads. A continuously mutating tenant gets a bounded retry error
    rather than an impossible hybrid posture cached as truth.
    """

    tenant_id = _tenant_id(request)
    revision_reader = getattr(hub_store, "overview_evidence_revision", None)
    if not callable(revision_reader):
        if require_revision:
            _raise_hub_overview_unavailable()
        return _HubOverviewSnapshot(
            severity=_hub_severity_snapshot(request),
            failing_frameworks=(_hub_failing_frameworks_snapshot(request) if include_details else set()),
            kev=_hub_kev_snapshot(request),
            top_risks=(_hub_top_risks(request) if include_details else []),
            revision=None,
            coverage=(_hub_coverage_snapshot(request, hub_store, None) if include_details else None),
        )

    def _read_revision() -> int:
        try:
            return int(revision_reader(tenant_id))
        except HTTPException:
            raise
        except Exception:
            _logger.debug("hub overview revision read failed", exc_info=False)
            _raise_hub_overview_unavailable()

    for _attempt in range(_HUB_SNAPSHOT_MAX_ATTEMPTS):
        revision = _read_revision()
        snapshot = _HubOverviewSnapshot(
            severity=_hub_severity_snapshot(request, revision=revision, strict=True),
            failing_frameworks=(_hub_failing_frameworks_snapshot(request, revision=revision, strict=True) if include_details else set()),
            kev=_hub_kev_snapshot(request, revision=revision, strict=True),
            top_risks=(_hub_top_risks(request, strict=True) if include_details else []),
            revision=revision,
            coverage=(_hub_coverage_snapshot(request, hub_store, revision) if include_details else None),
        )
        if _read_revision() == revision:
            return snapshot

    raise HTTPException(
        status_code=503,
        detail="Overview evidence changed during read; retry the request.",
        headers={"Retry-After": "1"},
    )


@finding_read_snapshot
def _build_overview(request: Request) -> dict[str, Any]:
    """Synchronous overview composition (runs in a worker thread, #3963).

    Serves a cached payload when the tenant's job-metadata fingerprint is
    unchanged within the TTL, so repeated landing-page reads don't refold the
    whole estate (#3963 follow-up). Cache misses (new/changed scan data or an
    expired entry) recompute and refresh the cache — but only ONCE per tenant
    per fingerprint: concurrent misses join the in-flight fold instead of
    stampeding it.
    """
    tenant_id = _tenant_id(request)
    store = _get_store()
    from agent_bom.api.compliance_hub_store import get_compliance_hub_store

    hub_store = get_compliance_hub_store()
    if callable(getattr(store, "overview_evidence_revision", None)):
        return _build_revisioned_overview(request, tenant_id, store, hub_store)
    jobs = store.list_all(tenant_id=tenant_id)
    hub_snapshot = _capture_hub_overview_snapshot(request, hub_store)
    hub_evidence_version = hub_snapshot.revision
    hub_severity = hub_snapshot.severity
    hub_failing_frameworks = hub_snapshot.failing_frameworks

    fingerprint = _overview_fingerprint(
        tenant_id,
        jobs,
        hub_severity,
        hub_failing_frameworks,
        hub_evidence_version or 0,
    )
    cached = _overview_cache_get(tenant_id, fingerprint)
    if cached is not None:
        return cached

    with _overview_cache_lock:
        flight = _overview_inflight.get(tenant_id)
        leader = flight is None or flight.fingerprint != fingerprint
        if leader:
            flight = _OverviewFlight(fingerprint=fingerprint)
            _overview_inflight[tenant_id] = flight

    assert flight is not None  # nosec B101 — narrowing; set on both branches
    if not leader:
        if flight.event.wait(timeout=_overview_singleflight_timeout()) and flight.payload is not None:
            return flight.payload
        # The leader failed or overran its budget. Recompute rather than serve
        # nothing — correctness beats de-duplication.
        payload = _compose_overview(
            request,
            tenant_id,
            jobs,
            hub_severity,
            hub_failing_frameworks,
            hub_evidence_version,
            hub_kev=hub_snapshot.kev,
            hub_top_risks=hub_snapshot.top_risks,
            hub_coverage=hub_snapshot.coverage,
        )
        _overview_cache_put(tenant_id, fingerprint, payload)
        return payload

    try:
        payload = _compose_overview(
            request,
            tenant_id,
            jobs,
            hub_severity,
            hub_failing_frameworks,
            hub_evidence_version,
            hub_kev=hub_snapshot.kev,
            hub_top_risks=hub_snapshot.top_risks,
            hub_coverage=hub_snapshot.coverage,
        )
        _overview_cache_put(tenant_id, fingerprint, payload)
        flight.payload = payload
        return payload
    finally:
        with _overview_cache_lock:
            if _overview_inflight.get(tenant_id) is flight:
                del _overview_inflight[tenant_id]
        flight.event.set()


def _build_revisioned_overview(request: Request, tenant_id: str, store: Any, hub_store: Any) -> dict[str, Any]:
    """Check durable revisions before materializing large persisted job results.

    Cache TTL and hub evidence validation remain unchanged. The job revision is
    checked around reads/composition; continuous mutation fails closed rather
    than caching an aggregate under the wrong evidence version.
    """

    def revision() -> str:
        try:
            return str(store.overview_evidence_revision(tenant_id))
        except Exception:
            _raise_hub_overview_unavailable()

    for _attempt in range(_HUB_SNAPSHOT_MAX_ATTEMPTS):
        before = revision()
        hub = _capture_hub_overview_snapshot(request, hub_store)
        fingerprint = (
            "job-revision:" + before + ":" + _overview_fingerprint(tenant_id, [], hub.severity, hub.failing_frameworks, hub.revision or 0)
        )
        if revision() != before:
            continue
        cached = _overview_cache_get(tenant_id, fingerprint)
        if cached is not None:
            return cached
        with _overview_cache_lock:
            flight = _overview_inflight.get(tenant_id)
            leader = flight is None or flight.fingerprint != fingerprint
            if leader:
                flight = _OverviewFlight(fingerprint=fingerprint)
                _overview_inflight[tenant_id] = flight
        assert flight is not None  # nosec B101 — set on both branches
        if not leader:
            if flight.event.wait(timeout=_overview_singleflight_timeout()) and flight.payload is not None:
                if revision() == before:
                    return flight.payload
                continue
            # A failed or slow leader does not authorize stale evidence. Retry
            # the bounded revision check rather than stampeding payload reads.
            continue
        try:
            from agent_bom.api.time_window import default_window_days

            aggregate_key = f"{tenant_id}|{before}|{hub.revision}|{default_window_days()}"
            scan_inputs = _scan_aggregate_get(aggregate_key) if hub.revision is not None else None
            jobs = [] if scan_inputs is not None else store.list_all(tenant_id=tenant_id)
            if revision() != before:
                continue
            payload = _compose_overview(
                request,
                tenant_id,
                jobs,
                hub.severity,
                hub.failing_frameworks,
                hub.revision,
                hub_kev=hub.kev,
                hub_top_risks=hub.top_risks,
                hub_coverage=hub.coverage,
                scan_inputs=scan_inputs,
                scan_cache_key=aggregate_key if hub.revision is not None else None,
            )
            if revision() != before:
                continue
            _overview_cache_put(tenant_id, fingerprint, payload)
            flight.payload = payload
            return payload
        finally:
            with _overview_cache_lock:
                if _overview_inflight.get(tenant_id) is flight:
                    del _overview_inflight[tenant_id]
            flight.event.set()
    raise HTTPException(
        status_code=503,
        detail="Overview evidence changed or is busy; retry the request.",
        headers={"Retry-After": "1"},
    )


def _compose_overview(
    request: Request,
    tenant_id: str,
    jobs: list[Any],
    hub_severity: dict[str, int],
    hub_failing_frameworks: set[str],
    hub_evidence_revision: int | None = None,
    *,
    hub_kev: int | None = None,
    hub_top_risks: list[dict[str, Any]] | None = None,
    hub_coverage: tuple[dict[str, dict[str, int]], str] | None = None,
    scan_inputs: dict[str, Any] | None = None,
    scan_cache_key: str | None = None,
) -> dict[str, Any]:
    """Fold scan evidence once per durable revision; refresh live overlays."""
    from agent_bom.api.cloud_scan_scopes import scanned_cloud_scopes
    from agent_bom.api.overview_cve_counts import compose_cve_domain, empty_cve_counts
    from agent_bom.api.stores import _jobs_is_compacted

    if scan_inputs is None:
        estate = _estate_rollup(jobs)
        from agent_bom.api.routes.compliance import _result_evidence_context, _result_has_runtime_signals

        runtime_results = []
        for job in jobs:
            if job.status != JobStatus.DONE or not job.result:
                continue
            mcp, agent, sources = _result_evidence_context(job.result)
            runtime_results.append(
                {
                    "has_mcp_context": mcp,
                    "has_agent_context": agent,
                    "scan_sources": sorted(sources),
                    "runtime_correlation": _result_has_runtime_signals(job.result),
                }
            )
        empty_hub = ({domain: _empty_severity() for domain in _COVERAGE_DOMAINS}, "complete")
        cves = empty_cve_counts()
        scan_inputs = {
            "cves": cves,
            "cves_complete": not any(_jobs_is_compacted(job) for job in jobs),
            "estate": estate,
            "exec_estate": _exec_estate(estate, jobs),
            "coverage": _current_coverage(jobs, empty_hub, cve_counts=cves),
            "posture": _posture_snapshot(jobs),
            "repo_scans": _repo_scan_count(jobs),
            "runtime_results": runtime_results,
            "cloud_scopes": scanned_cloud_scopes(jobs),
            "issue_counts": issue_severity_counts(request, jobs),
        }
        if scan_cache_key:
            _scan_aggregate_put(scan_cache_key, scan_inputs, jobs)
    estate = scan_inputs["estate"]
    exec_estate = scan_inputs["exec_estate"]
    if hub_coverage is None:
        from agent_bom.api.compliance_hub_store import get_compliance_hub_store

        hub_coverage = _hub_coverage_snapshot(request, get_compliance_hub_store(), hub_evidence_revision)
    coverage = []
    for lane in scan_inputs["coverage"]:
        severity = _combined_severity(lane["severity"], hub_coverage[0][lane["domain"]])
        coverage.append(
            {
                **lane,
                "severity": severity,
                "count": sum(severity.values()),
                "evidence_status": hub_coverage[1],
                "count_exact": hub_coverage[1] == "complete",
            }
        )
    if hub_kev is None:
        hub_kev = _hub_kev_snapshot(request, revision=hub_evidence_revision)
    posture = _exec_posture(
        request,
        scan_inputs["posture"],
        exec_estate,
        hub_severity,
        hub_kev,
        hub_failing_frameworks,
        issue_severity=(issue_counts := scan_inputs.get("issue_counts")),
    )
    runtime_jobs = [SimpleNamespace(status=JobStatus.DONE, result=result) for result in scan_inputs["runtime_results"]]
    runtime = _runtime_snapshot(request, runtime_jobs)
    cost = _cost_snapshot(request)
    identity = _identity_snapshot(request)

    # Sum EVERY hub band (incl. ``none`` / vendor-specific), not just the six
    # canonical keys, so the hub-findings count never silently drops a band the
    # exec total (via ``_combined_severity``) still carries.
    hub_findings = sum(int(v or 0) for v in hub_severity.values())
    # Headline = the issue counts the grade and tiles use; occurrences stay in finding_counts (#3961).
    exec_counts = _reconciled_exec_counts(exec_estate, hub_severity, hub_kev)
    headline_critical, headline_high = (int((issue_counts or exec_counts)[key]) for key in ("critical", "high"))
    critical_high = headline_critical + headline_high

    cloud_scopes = scan_inputs.get("cloud_scopes")
    if cloud_scopes is None:
        cloud_scopes = scanned_cloud_scopes(jobs)
    cloud_accounts = _cloud_account_count(request, cloud_scopes)
    repo_scans = scan_inputs["repo_scans"]
    vuln_domain = compose_cve_domain(
        scan_inputs.get("cves", empty_cve_counts()),
        hub_coverage[0].get("_cves", empty_cve_counts()),
        scan_complete=scan_inputs.get("cves_complete", False),
        hub_status=hub_coverage[1] if "_cves" in hub_coverage[0] else "unavailable",
        packages=estate["unique_packages"],
        graph_href=_cloud_graph_href,
    )

    # Fold hub-ingested findings into the exec top-risk strip so a
    # connector/bulk-ingested estate (scan jobs alone) no longer renders an empty
    # strip while a million open findings drive the grade (P0 #1).
    if hub_top_risks is None:
        hub_top_risks = _hub_top_risks(request)
    top_risks = _merge_top_risks(estate["top_risks"], hub_top_risks)

    domains = {
        "cloud": {
            "label": "Cloud posture",
            "href": "/connections",
            "graph_href": _cloud_graph_href(estate["severity"]),
            "metric": cloud_accounts,
            "metric_label": "accounts connected",
            "status": "ok" if cloud_accounts > 0 else "idle",
            "detail": {
                "accounts": cloud_accounts,
                "sources": estate["sources"],
            },
        },
        "vuln": vuln_domain,
        "code": {
            "label": "Code / repo",
            "href": "/scan",
            "graph_href": _graph_drill_href(layers="directory,source_file,config_file,package,framework,vulnerability"),
            "metric": repo_scans,
            "metric_label": "repo scans",
            "status": "ok" if repo_scans > 0 else "idle",
            "detail": {"repo_scans": repo_scans, "packages": estate["unique_packages"]},
        },
        "runtime": {
            "label": "Runtime",
            "href": "/gateway",
            "graph_href": _graph_drill_href(relationships="runtime"),
            "metric": runtime["active_surfaces"],
            "metric_label": "active surfaces",
            "status": "ok" if runtime["active_surfaces"] > 0 else "idle",
            "detail": runtime,
        },
        "cost": {
            "label": "LLM Cost",
            "href": "/cost",
            "metric": round(float(cost["total_cost_usd"]), 2) if cost["available"] else None,
            "metric_label": "USD estimated",
            "status": ("ok" if cost["total_calls"] > 0 else "idle") if cost["available"] else "unavailable",
            "detail": cost,
        },
        "identity": {
            "label": "NHI / Identity",
            "href": "/identity",
            "graph_href": _graph_drill_href(layers="agent,user,role,policy", relationships="governance"),
            "metric": identity["managed_identities"],
            "metric_label": "managed identity records",
            "status": _identity_status(identity),
            "detail": identity,
        },
        "ops": {
            "label": "Ops",
            "href": "/jobs",
            "metric": estate["scan_count"],
            "metric_label": "completed scans",
            "status": "warn" if estate["failed_count"] > 0 else ("ok" if estate["scan_count"] > 0 else "idle"),
            "detail": {
                "done": estate["done_count"],
                "failed": estate["failed_count"],
                "running": estate["running_count"],
                "packages": estate["unique_packages"],
            },
        },
    }

    return {
        "schema_version": "overview.v1",
        "tenant_id": tenant_id,
        "posture": posture,
        "finding_counts": {key: exec_counts[key] for key in ("critical", "high", "medium", "low", "unrated", "total", "kev")},
        "issue_counts": issue_counts_payload(issue_counts),
        "headline": {
            "critical": headline_critical,
            "high": headline_high,
            "critical_high": critical_high,
            "kev": exec_counts["kev"],
            "credential_exposed": exec_estate["credential_exposed"],
            "scans": estate["scan_count"],
            "latest_scan_at": estate["latest_scan_at"],
            "hub_findings": hub_findings,
        },
        "domains": domains,
        "coverage": coverage,
        "top_risks": top_risks,
    }


@router.get("/overview/score-config", **documented(governance_b.OverviewScoreConfigResponse), tags=["overview"])
def get_overview_score_config(request: Request) -> dict[str, Any]:
    """Return the tenant's effective exec risk-score model + display config (#3940).

    Read-only view of the documented default weighting model, any tenant
    overrides, the effective weights/thresholds, and the active display format.
    """
    from agent_bom.api.exec_score_config import exec_score_config_runtime

    return exec_score_config_runtime(_tenant_id(request))


@router.put("/overview/score-config", tags=["overview"])
def update_overview_score_config(request: Request, req: ExecScoreConfigUpdateRequest) -> dict[str, Any]:
    """Update the tenant's exec risk-score weights, thresholds, or display format.

    Admin-gated (mutating ``/v1`` verb). The body is canonicalized and clamped
    server-side — out-of-range weights are pinned into range, unknown keys are
    dropped, and an invalid display format falls back to the default, so a bad
    override never raises.
    """
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.exec_score_config import exec_score_config_runtime, set_exec_score_config

    tenant_id = _tenant_id(request)
    updates = req.model_dump(exclude_none=True)
    if not updates:
        from fastapi import HTTPException

        raise HTTPException(status_code=400, detail="Provide at least one of weights, grade_thresholds, or display_format.")

    actor = getattr(request.state, "api_key_name", "") or "system"
    canonical = set_exec_score_config(tenant_id, updates)
    log_action(
        "overview.score_config_updated",
        actor=actor,
        resource=f"tenant/{tenant_id}",
        tenant_id=tenant_id,
        updated_fields=sorted(updates),
        display_format=canonical.get("display_format"),
    )
    return exec_score_config_runtime(tenant_id)


@router.delete("/overview/score-config", tags=["overview"], status_code=204)
def reset_overview_score_config(request: Request) -> None:
    """Clear the tenant's exec risk-score overrides (revert to defaults)."""
    from agent_bom.api.audit_log import log_action
    from agent_bom.api.exec_score_config import clear_exec_score_config

    tenant_id = _tenant_id(request)
    actor = getattr(request.state, "api_key_name", "") or "system"
    cleared = clear_exec_score_config(tenant_id)
    if cleared:
        log_action(
            "overview.score_config_reset",
            actor=actor,
            resource=f"tenant/{tenant_id}",
            tenant_id=tenant_id,
        )


_EXPORTS = {
    "_OVERVIEW_CACHE_TTL_SECONDS_DEFAULT": "agent_bom.api.overview_cache",
    "_overview_cache": "agent_bom.api.overview_cache",
    "_SCAN_AGGREGATE_MAX_BYTES": "agent_bom.api.overview_cache",
    "_SCAN_AGGREGATE_MAX_ENTRIES": "agent_bom.api.overview_cache",
    "_SCAN_AGGREGATE_TTL": "agent_bom.api.overview_cache",
    "_scan_aggregate_cache": "agent_bom.api.overview_cache",
    "_OVERVIEW_SINGLEFLIGHT_TIMEOUT_SECONDS": "agent_bom.api.overview_cache",
    "_overview_cache_ttl": "agent_bom.api.overview_cache",
    "_reset_overview_cache": "agent_bom.api.overview_cache",
    "_SEVERITY_KEYS": "agent_bom.api.overview_rollup",
    "_UNRATED_KEY": "agent_bom.api.overview_rollup",
    "_bucket": "agent_bom.api.overview_rollup",
    "_severity_from_summary": "agent_bom.api.overview_rollup",
    "_SEVERITY_RISK_FLOOR": "agent_bom.api.overview_rollup",
    "_UNRATED_RISK_FLOOR": "agent_bom.api.overview_rollup",
    "_row_risk_score": "agent_bom.api.overview_rollup",
    "_finding_top_risk": "agent_bom.api.overview_rollup",
    "_row_domain": "agent_bom.api.overview_rollup",
    "_row_lenses": "agent_bom.api.overview_rollup",
    "_HUB_TOP_RISK_LIMIT": "agent_bom.api.overview_hub",
    "_current_open_scan_findings": "agent_bom.api.overview_rollup",
    "_current_scan_severity": "agent_bom.api.overview_rollup",
    "_fold_current_coverage": "agent_bom.api.overview_rollup",
    "_status_for": "agent_bom.api.overview_projection",
}


def __getattr__(name: str) -> Any:
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module), name)
    globals()[name] = value
    return value
