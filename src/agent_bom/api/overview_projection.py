"""Per-domain and posture projections for Overview."""

from __future__ import annotations

import logging
from typing import Any, cast

from fastapi import Request

from agent_bom.api.exec_posture import tenant_exec_posture
from agent_bom.api.models import JobStatus
from agent_bom.api.overview_rollup import _combined_severity, _tenant_id
from agent_bom.api.stores import _get_fleet_store
from agent_bom.fleet.trust_scoring import LOW_TRUST_THRESHOLD

_logger = logging.getLogger("agent_bom.api.routes.overview")


def _posture_snapshot(jobs: list[Any]) -> dict[str, Any]:
    """Letter grade + score from the latest completed scan (same as /v1/posture)."""
    from agent_bom.api.findings_current import latest_current_scan_job

    job = latest_current_scan_job(jobs, require_authoritative_evidence=True)
    if job is not None:
        result = cast(dict[str, Any], job.result)
        scorecard = result.get("posture_scorecard")
        if isinstance(scorecard, dict) and scorecard:
            return {
                "grade": scorecard.get("grade", "N/A"),
                "score": scorecard.get("score", 0),
                "summary": scorecard.get("summary", ""),
            }
        summary = result.get("summary")
        if isinstance(summary, dict) and (summary.get("total_vulnerabilities") or summary.get("total_findings")):
            from agent_bom.posture import _score_to_grade

            critical = int(summary.get("critical_unified_findings") or summary.get("critical_findings") or 0)
            high = int(summary.get("high_unified_findings") or 0)
            total = int(summary.get("total_vulnerabilities") or summary.get("total_findings") or 0)
            penalty = min(100.0, critical * 12.0 + high * 6.0 + max(0, total - critical - high) * 1.5)
            score = max(0.0, round(100.0 - penalty, 1))
            return {
                "grade": _score_to_grade(score),
                "score": score,
                "summary": f"{total} finding(s) from latest completed scan",
            }
    return {"grade": "N/A", "score": 0, "summary": "No completed scans available"}


def _runtime_snapshot(request: Request, jobs: list[Any]) -> dict[str, Any]:
    """Runtime signals (gateway / proxy / traces / mesh) for the Runtime domain.

    Reuses the same deployment-context derivation that powers nav badges so the
    overview and the rest of the UI agree on what runtime surfaces are live.
    """
    try:
        from agent_bom.api.routes.compliance import _derive_deployment_context

        ctx = _derive_deployment_context(request, jobs)
    except Exception:  # pragma: no cover - defensive; degrade to empty signals
        _logger.debug("deployment-context derivation failed", exc_info=False)
        ctx = {}
    active = sum(1 for key in ("has_gateway", "has_proxy", "has_traces", "has_mesh") if ctx.get(key))
    return {
        "has_gateway": bool(ctx.get("has_gateway")),
        "has_proxy": bool(ctx.get("has_proxy")),
        "has_traces": bool(ctx.get("has_traces")),
        "has_mesh": bool(ctx.get("has_mesh")),
        "deployment_mode": ctx.get("deployment_mode", "local"),
        "active_surfaces": active,
    }


def _cost_snapshot(request: Request) -> dict[str, Any]:
    """LLM spend rollup from the cost store (same source as /v1/observability/costs)."""
    try:
        from agent_bom.api.cost_store import get_cost_store

        store = get_cost_store()
        report = store.report_totals(_tenant_id(request))
        budget = store.get_budget(_tenant_id(request), "")
        return {
            **report,
            "available": True,
            "budget_configured": budget is not None,
        }
    except Exception:  # pragma: no cover - cost store optional
        _logger.debug("cost snapshot failed", exc_info=False)
        return {"available": False, "total_cost_usd": None, "total_calls": None, "agents": None, "budget_configured": None}


def _identity_snapshot(request: Request) -> dict[str, Any]:
    """NHI / fleet counts from the identity + fleet stores."""
    tenant_id = _tenant_id(request)
    identities: int | None = None
    try:
        from agent_bom.api.agent_identity_store import get_agent_identity_store

        identities = get_agent_identity_store().count(tenant_id)
    except Exception:  # pragma: no cover - identity store optional
        _logger.debug("identity snapshot failed", exc_info=False)

    fleet_total: int | None = None
    low_trust: int | None = None
    try:
        agents = _get_fleet_store().list_by_tenant(tenant_id)
        fleet_total = len(agents)
        low_trust = sum(1 for a in agents if float(getattr(a, "trust_score", 0.0) or 0.0) < LOW_TRUST_THRESHOLD)
    except Exception:  # pragma: no cover - fleet store optional
        _logger.debug("fleet snapshot failed", exc_info=False)

    return {
        "count_definition": "managed identity records by lifecycle status; fleet registrations are separate",
        "managed_identities_available": identities is not None,
        "fleet_agents_available": fleet_total is not None,
        "managed_identities": identities,
        "fleet_agents": fleet_total,
        "low_trust_agents": low_trust,
    }


def _exec_posture(
    request: Request,
    scan_posture: dict[str, Any],
    estate: dict[str, Any],
    hub_severity: dict[str, int],
    hub_kev: int = 0,
    hub_failing_frameworks: set[str] | None = None,
    issue_severity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The tenant exec posture; see :func:`agent_bom.api.exec_posture.tenant_exec_posture`."""
    occurrences = _combined_severity(estate["severity"], hub_severity)
    return tenant_exec_posture(_tenant_id(request), scan_posture, estate, occurrences, hub_kev, hub_failing_frameworks, issue_severity)


def _cloud_account_count(request: Request, scanned_scopes: dict[str, Any] | None) -> int:
    """Covered cloud accounts: connected plus scanned/pushed scopes, deduped."""
    try:
        from agent_bom.api.cloud_scan_scopes import cloud_account_summary
        from agent_bom.api.connection_store import get_connection_store

        connections = get_connection_store().list_for_tenant(_tenant_id(request))
        return int(cloud_account_summary(connections, scanned_scopes)["count"])
    except Exception:  # pragma: no cover - connection store optional
        _logger.debug("cloud account snapshot failed", exc_info=False)
        return 0


def _repo_scan_count(jobs: list[Any]) -> int:
    """Count completed jobs that targeted a remote repo URL or repo scan source."""
    count = 0
    for job in jobs:
        if job.status != JobStatus.DONE:
            continue
        request = getattr(job, "request", None)
        repo_url = getattr(request, "repo_url", None) if request is not None else None
        if isinstance(repo_url, str) and repo_url.strip():
            count += 1
            continue
        result = cast(dict[str, Any], getattr(job, "result", None) or {})
        sources = result.get("scan_sources") or []
        if isinstance(sources, list) and any(
            isinstance(src, str) and ("repo" in src.lower() or "project" in src.lower()) for src in sources
        ):
            count += 1
    return count


def _status_for(critical: int, high: int) -> str:
    if critical > 0:
        return "critical"
    if high > 0:
        return "warn"
    return "ok"


def _identity_status(identity: dict[str, Any]) -> str:
    if identity["managed_identities"] is None or identity["fleet_agents"] is None:
        return "unavailable"
    if (identity["low_trust_agents"] or 0) > 0:
        return "warn"
    if identity["fleet_agents"] or identity["managed_identities"]:
        return "ok"
    return "idle"
