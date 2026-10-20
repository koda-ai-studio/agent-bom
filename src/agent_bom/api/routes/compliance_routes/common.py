"""Tenant-scoped compliance and posture readers shared by the compliance routes."""

from __future__ import annotations

import logging
from typing import Any, cast

from fastapi import Request

from agent_bom.api import time_window
from agent_bom.api.credential_rotation import build_credential_rotation_governance
from agent_bom.api.finding_read_context import finding_read_snapshot
from agent_bom.api.models import JobStatus
from agent_bom.api.posture_counts_cache import POSTURE_COUNTS_CACHE, cached_posture_block
from agent_bom.api.routes.compliance_routes.evidence import (
    _build_aisvs_payload,
    _result_evidence_context,
    _result_has_runtime_signals,
)
from agent_bom.api.scan_finding_read import iter_tenant_scan_spine_findings
from agent_bom.api.stores import (
    _get_credential_ref_store,
    _get_fleet_store,
    _get_graph_store,
    _get_policy_store,
    _get_store,
)
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.demo_estate.boot_seed import DEMO_SEEDING_SUMMARY as _DEMO_SEEDING_SUMMARY
from agent_bom.demo_estate.boot_seed import demo_estate_seeding
from agent_bom.evidence import EvidenceTier, redact_for_persistence
from agent_bom.framework_evidence import framework_evidence_slugs
from agent_bom.security import sanitize_text

_logger = logging.getLogger(__name__)

_CLUSTER_SCAN_SOURCES = {"gpu_infra", "k8s"}
_CI_CD_SCAN_SOURCES = {"github_actions"}
_REGISTRY_SCAN_SOURCES = {"external_scan", "image", "sbom"}
# Source receipts identify collection, independently of the API host or store.
# SBOM, image and external results can arrive through ingestion alone.
_LOCAL_SCAN_SOURCES = {"agent_discovery", "filesystem"}

_CLUSTER_ENVIRONMENTS = {"aks", "cluster", "eks", "gke", "k8s", "kubernetes"}


def _tenant_id(request: Request) -> str:
    return require_request_tenant_id(request)


def _tenant_jobs(request: Request) -> list:
    return cast(list, _get_store().list_all(tenant_id=_tenant_id(request)))


def _credential_rotation_governance(tenant_id: str) -> dict[str, Any]:
    try:
        credentials = _get_credential_ref_store().list_all(tenant_id=tenant_id)
    except RuntimeError:
        credentials = []
    return build_credential_rotation_governance(credentials, tenant_id=tenant_id)


def _latest_aisvs_benchmark_from_jobs(jobs: list[Any]) -> dict[str, Any]:
    from agent_bom.api.findings_current import current_scan_jobs, scan_evidence_authority_key

    latest: tuple[tuple[str, str, str], str, dict[str, Any]] | None = None
    for job in current_scan_jobs(
        jobs,
        since=None,
        scan_id=None,
        require_authoritative_evidence=True,
    ):
        result = cast(dict[str, Any], job.result)
        benchmark = result.get("aisvs_benchmark") or result.get("aisvs_benchmark_data")
        if not isinstance(benchmark, dict):
            continue
        authority = scan_evidence_authority_key(job)
        scan_id = str(result.get("scan_id") or getattr(job, "job_id", ""))
        if latest is None or authority > latest[0]:
            latest = (authority, scan_id, benchmark)

    if latest is None:
        return _build_aisvs_payload(None)
    authority, latest_scan_id, benchmark = latest
    return _build_aisvs_payload(benchmark, scan_id=latest_scan_id, measured_at=authority[1] or None)


def _compliance_evidence_authority_key(job: Any, _row: dict[str, Any]) -> tuple[str, str, str]:
    """Compatibility wrapper around the canonical scan authority key."""

    from agent_bom.api.findings_current import scan_evidence_authority_key

    # Kept as a compatibility seam for callers/tests; scan-level authority is
    # canonicalized in findings_current and shared with Overview/Findings.
    return scan_evidence_authority_key(job)


def _tenant_has_proxy_alerts(tenant_id: str) -> bool:
    """Return True when the in-process proxy-alert ring buffer holds any
    alerts for ``tenant_id``.

    Proxy alerts ingested via ``/v1/proxy/audit`` land in
    ``agent_bom.api.routes.proxy._proxy_alerts`` — a bounded deque that is
    independent of the scan-job result store and the gateway policy_store.
    The ingestion path tags each record with ``tenant_id`` so this helper
    can scope correctly on multi-tenant deployments. Older records that
    pre-date the tagging carry no ``tenant_id``; for those we fall back to
    a fleet-wide signal so a recently-ingested alert still surfaces in
    posture even if its tenant attribution was lost on restart.
    """
    try:
        from agent_bom.api.routes.proxy import _proxy_alerts
    except ImportError:  # pragma: no cover — defensive
        return False
    if not _proxy_alerts:
        return False
    for alert in _proxy_alerts:
        alert_tenant = alert.get("tenant_id")
        if alert_tenant is None or alert_tenant == tenant_id:
            return True
    return False


def _derive_deployment_context(request: Request, jobs: list[Any]) -> dict[str, Any]:
    tenant_id = _tenant_id(request)
    scan_sources: set[str] = set()
    has_mcp_context = False
    has_agent_context = False
    has_runtime_signals = False
    scan_count = 0

    for job in jobs:
        if job.status != JobStatus.DONE or not job.result:
            continue
        scan_count += 1
        result = cast(dict[str, Any], job.result)
        result_has_mcp, result_has_agent, result_sources = _result_evidence_context(result)
        has_mcp_context = has_mcp_context or result_has_mcp
        has_agent_context = has_agent_context or result_has_agent
        scan_sources.update(result_sources)
        has_runtime_signals = has_runtime_signals or _result_has_runtime_signals(result)

    fleet_agents = _get_fleet_store().list_by_tenant(tenant_id)
    has_fleet_ingest = len(fleet_agents) > 0
    has_cluster_scan = bool(scan_sources & _CLUSTER_SCAN_SOURCES) or any(
        str(getattr(agent, "environment", "") or "").strip().lower() in _CLUSTER_ENVIRONMENTS for agent in fleet_agents
    )
    has_ci_cd_scan = bool(scan_sources & _CI_CD_SCAN_SOURCES)
    has_local_scan = bool(scan_sources & _LOCAL_SCAN_SOURCES)
    has_registry = bool(scan_sources & _REGISTRY_SCAN_SOURCES)

    policy_store = _get_policy_store()
    policies = policy_store.list_policies(tenant_id=tenant_id)
    policy_audit = policy_store.list_audit_entries(limit=1, tenant_id=tenant_id)
    has_gateway = bool(policies)

    # Dedicated proxy alerts are independent of scans and policy audit entries;
    # count them so reported runtime activity remains visible on the dashboard.
    has_proxy_alerts = _tenant_has_proxy_alerts(tenant_id)

    has_proxy = bool(policy_audit) or has_runtime_signals or has_proxy_alerts
    has_traces = bool(policy_audit) or has_runtime_signals or has_proxy_alerts
    has_mesh = (
        has_fleet_ingest
        or bool(scan_count and has_agent_context and has_mcp_context)
        or bool(has_runtime_signals and (has_agent_context or has_fleet_ingest))
    )

    active_modes = sum((has_local_scan, has_fleet_ingest, has_cluster_scan, has_ci_cd_scan))
    if active_modes > 1:
        deployment_mode = "hybrid"
    elif has_cluster_scan:
        deployment_mode = "cluster"
    elif has_fleet_ingest:
        deployment_mode = "fleet"
    elif has_local_scan:
        deployment_mode = "local"
    elif has_ci_cd_scan:
        deployment_mode = "ci"
    elif scan_count or has_runtime_signals or has_proxy_alerts:
        deployment_mode = "ingest"
    else:
        deployment_mode = "unknown"

    return {
        "deployment_mode": deployment_mode,
        "has_local_scan": has_local_scan,
        "has_fleet_ingest": has_fleet_ingest,
        "has_cluster_scan": has_cluster_scan,
        "has_ci_cd_scan": has_ci_cd_scan,
        "has_mesh": has_mesh,
        "has_gateway": has_gateway,
        "has_proxy": has_proxy,
        "has_traces": has_traces,
        "has_registry": has_registry,
        "has_mcp_context": has_mcp_context,
        "has_agent_context": has_agent_context,
        "scan_sources": sorted(scan_sources),
        "scan_count": scan_count,
    }


def _current_narrative_evidence(request: Request) -> dict[str, Any] | None:
    """Return the same persisted current finding snapshot the queue exposes."""
    from agent_bom.api.finding_snapshot_read import current_findings_snapshot

    snapshot = current_findings_snapshot(request)
    if not snapshot["findings"] and not snapshot["completed_scan_count"]:
        return None
    return snapshot


@finding_read_snapshot
def _posture_scorecard_impl(request: Request) -> dict:
    """Select the latest scan and compose the exec posture over one parse of each job payload."""
    from agent_bom.api.findings_current import latest_current_scan_job
    from agent_bom.api.posture_scan_snapshot import revision_cached, scan_posture_inputs

    latest_result = scan_posture_inputs(
        _get_store(),
        require_request_tenant_id(request),
        lambda: latest_current_scan_job(_tenant_jobs(request), require_authoritative_evidence=True),
    )

    if latest_result is None:
        seeding = demo_estate_seeding()
        return {
            "grade": "N/A",
            "score": 0,
            "summary": _DEMO_SEEDING_SUMMARY if seeding else "No completed scans available",
            "dimensions": {},
            "no_data": True,
            "demo_estate_seeding": seeding,
        }

    # Did-we-scan guard: a completed scan that examined ZERO gradable artifacts
    # must not report a passing grade. Mirror the honest no-data / N/A treatment
    # rather than surfacing a fallback "B" from empty-default dimensions.
    summary = latest_result.get("summary") or {}
    examined_artifacts = (
        int(summary.get("total_packages") or 0)
        + int(summary.get("total_mcp_servers") or 0)
        + int(summary.get("total_findings") or 0)
        + int(summary.get("total_vulnerabilities") or 0)
    )
    if examined_artifacts == 0:
        return {
            "grade": "N/A",
            "score": 0,
            "summary": "No artifacts scanned — posture grade unavailable. Connect a surface or run a scan to grade posture.",
            "dimensions": {},
            "no_data": True,
        }

    scorecard = latest_result.get("posture_scorecard")
    if scorecard:
        from agent_bom.api.exec_posture import canonical_posture_payload, tenant_posture_dimensions

        tenant = revision_cached(
            _get_store(), require_request_tenant_id(request), "dimensions", lambda: tenant_posture_dimensions(_tenant_jobs(request))
        )
        if tenant is None:
            return canonical_posture_payload(
                request,
                cast(dict, scorecard),
                dimensions_basis={
                    "basis": "latest_scan",
                    "scan_id": latest_result.get("scan_id"),
                    "completed_at": latest_result.get("completed_at"),
                },
            )
        return canonical_posture_payload(
            request,
            {**cast(dict, scorecard), "dimensions": tenant["dimensions"]},
            dimensions_basis=tenant["basis"],
        )

    return {
        "grade": "N/A",
        "score": 0,
        "summary": "Scorecard not computed for this scan",
        "dimensions": {},
        "no_data": True,
    }


_POSTURE_COUNTS_CACHE = POSTURE_COUNTS_CACHE
_cached_posture_block = cached_posture_block


def _cached_issue_severity_counts(request: Request, tenant_jobs: list[Any]) -> dict[str, Any]:
    from agent_bom.api.finding_snapshot_read import issue_severity_counts

    return _cached_posture_block(request, tenant_jobs, "issues", lambda: issue_severity_counts(request))


def estate_agent_count(tenant_id: str) -> dict[str, Any]:
    """Count canonical agent nodes in the inventory's current graph scope.

    The node page applies the same tenant, snapshot and entity-type predicates
    without computing finding facets or joining every incident relationship.
    """
    try:
        scan_id, _, _, total, _ = _get_graph_store().page_nodes(
            tenant_id=tenant_id,
            entity_types={"agent"},
            limit=1,
        )
    except Exception as exc:  # noqa: BLE001
        _logger.warning("Estate agent count unavailable: %s", sanitize_text(exc))
        return {"total": None, "scan_id": None, "basis": "graph_agents"}
    return {"total": int(total), "scan_id": scan_id or None, "basis": "graph_agents"}


def _cached_estate_agent_count(request: Request, tenant_jobs: list[Any]) -> dict[str, Any]:
    tenant_id = require_request_tenant_id(request)
    return _cached_posture_block(request, tenant_jobs, "agents", lambda: estate_agent_count(tenant_id))


@finding_read_snapshot
def _get_posture_counts_impl(request: Request) -> dict:
    """Synchronous posture-count composition, executed in a worker thread."""
    from agent_bom.api.exec_posture import posture_evidence_blocks

    tenant_jobs = _tenant_jobs(request)
    reconciled, compound, issues = posture_evidence_blocks(request, tenant_jobs)
    counts: dict[str, Any] = {
        "critical": reconciled["critical"],
        "high": reconciled["high"],
        "medium": reconciled["medium"],
        "low": reconciled["low"],
        "unrated": reconciled["unrated"],
        "total": reconciled["total"],
        "kev": reconciled["kev"],
        "compound_issues": compound["count"],
    }
    counts["issues"] = issues
    counts["agents"] = _cached_estate_agent_count(request, tenant_jobs)

    counts.update(_derive_deployment_context(request, tenant_jobs))
    tenant_id = require_request_tenant_id(request)
    from agent_bom.api.cloud_scan_scopes import scanned_cloud_scopes
    from agent_bom.api.service_registry import derive_service_registry

    cloud_scopes = _cached_posture_block(request, tenant_jobs, "cloud_scopes", lambda: scanned_cloud_scopes(tenant_jobs))
    counts["services"] = derive_service_registry(tenant_id, dict(counts), scanned_cloud_scopes=cloud_scopes)["services"]
    return counts


def _native_hub_findings(request: Request) -> list[dict[str, Any]]:
    """Return native scan findings in the compliance-hub list shape.

    The hub posture endpoint already aggregates native scans and external
    ingests together. This keeps the list endpoint aligned with that contract
    so operators can drill into both sides of the combined posture count.
    """
    from agent_bom.api.scan_finding_projection import _iter_scan_findings
    from agent_bom.compliance_coverage import TAG_MAPPED_FRAMEWORKS
    from agent_bom.compliance_hub import select_frameworks
    from agent_bom.finding import FindingSource, FindingType

    slug_to_tag_field: tuple[tuple[str, str], ...] = tuple((metadata.slug, metadata.tag_field) for metadata in TAG_MAPPED_FRAMEWORKS)
    rows: list[dict[str, Any]] = []
    for job in _tenant_jobs(request):
        if job.status != JobStatus.DONE or not job.result:
            continue
        for row in _iter_scan_findings(job):
            package_name = str(row.get("package") or row.get("package_name") or "")
            vulnerability_id = str(row.get("vulnerability_id") or row.get("cve_id") or row.get("id") or "")
            has_mcp_context = bool(row.get("affected_agents") or row.get("affected_servers"))
            source = FindingSource.MCP_SCAN if has_mcp_context else FindingSource.SBOM
            asset_type = "mcp_server" if has_mcp_context else "package"
            frameworks = [slug for slug, field in slug_to_tag_field if row.get(field)]
            if not frameworks:
                frameworks = select_frameworks(source, asset_type=asset_type, finding_type=FindingType.CVE)
            payload = {
                **row,
                "id": row.get("id") or f"{job.job_id}:{vulnerability_id}:{package_name}",
                "title": row.get("title") or f"{vulnerability_id or 'Vulnerability'} in {package_name or 'native scan asset'}",
                "finding_type": FindingType.CVE.value,
                "source": source.value,
                "origin": "native_scan",
                "asset": {
                    "name": package_name or vulnerability_id or "native scan asset",
                    "asset_type": asset_type,
                    "identifier": f"pkg:{package_name}" if package_name else None,
                    "location": None,
                    "stable_id": None,
                },
                "scan_id": job.job_id,
                "applicable_frameworks": frameworks,
                "effective_severity": row.get("severity", "unknown"),
            }
            clean = redact_for_persistence(payload, EvidenceTier.SAFE_TO_STORE)
            if isinstance(clean, dict):
                rows.append(clean)
    return rows


def _get_hub_posture_impl(request: Request) -> dict:
    """Synchronous body of :func:`get_hub_posture` (runs in a worker thread)."""
    from agent_bom.api.compliance_hub_store import get_compliance_hub_store
    from agent_bom.compliance_coverage import normalize_framework_slug

    tenant_id = _tenant_id(request)
    store = get_compliance_hub_store()
    severity_breakdown = getattr(store, "severity_breakdown", None)
    framework_counts_fn = getattr(store, "framework_slug_counts", None)
    if callable(severity_breakdown) and callable(framework_counts_fn):
        hub_severity_counts = severity_breakdown(tenant_id)
        hub_framework_counts = framework_counts_fn(tenant_id)
        hub_total = store.count(tenant_id)
    else:
        hub_findings = store.list(tenant_id)
        hub_total = len(hub_findings)
        hub_severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
        hub_framework_counts = {}
        for f in hub_findings:
            sev = (f.get("severity") or "unknown").lower()
            hub_severity_counts[sev] = hub_severity_counts.get(sev, 0) + 1
            for slug in f.get("applicable_frameworks") or []:
                canonical = normalize_framework_slug(str(slug))
                hub_framework_counts[canonical] = hub_framework_counts.get(canonical, 0) + 1

    native_framework_counts, native_total = _native_framework_counts(tenant_id)
    combined: dict[str, int] = {}
    for slug, count in native_framework_counts.items():
        combined[slug] = combined.get(slug, 0) + count
    for slug, count in hub_framework_counts.items():
        combined[slug] = combined.get(slug, 0) + count

    return {
        "totals": {
            "native": native_total,
            "hub": hub_total,
            "combined": native_total + hub_total,
        },
        "framework_counts": {
            "native": dict(sorted(native_framework_counts.items())),
            "hub": dict(sorted(hub_framework_counts.items())),
            "combined": dict(sorted(combined.items())),
        },
        "hub_severity_breakdown": hub_severity_counts,
        # The /v1/findings?framework= drill-through definition; hub rows are bulk-ingested, so their
        # declared applicable_frameworks are part of it.
        "framework_count_basis": "control_tag_evidence",
    }


def _native_framework_counts(tenant_id: str) -> tuple[dict[str, int], int]:
    """Open scan findings in the default window per framework, by the drill-through's evidence definition."""
    since = time_window.window_since_iso(time_window.normalize_window_days(None))
    rows = iter_tenant_scan_spine_findings(tenant_id, since=since, status="open", sanitize=False)
    counts: dict[str, int] = {}
    for row in rows:
        for slug in framework_evidence_slugs(row):
            counts[slug] = counts.get(slug, 0) + 1
    return counts, len(rows)
