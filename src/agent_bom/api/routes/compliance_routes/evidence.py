"""Pure compliance evidence shaping shared by the compliance routes.

Nothing here reads a store or the request: callers pass the tenant's scan jobs
in, so these helpers stay outside the API import tangle.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from agent_bom.api.models import JobStatus

if TYPE_CHECKING:
    from agent_bom.output.compliance_narrative import ComplianceNarrative


def _normalize_csv_filter(value: str | None) -> set[str]:
    if not value:
        return set()
    return {item.strip().lower() for item in value.split(",") if item.strip()}


def _aisvs_summary(benchmark: dict[str, Any]) -> dict[str, int | float]:
    checks_value = benchmark.get("checks")
    checks: list[Any] = checks_value if isinstance(checks_value, list) else []
    status_counts = {"pass": 0, "fail": 0, "error": 0, "not_applicable": 0}
    for check in checks:
        if not isinstance(check, dict):
            continue
        status = str(check.get("status") or "").lower()
        if status in status_counts:
            status_counts[status] += 1

    if not checks:
        status_counts["pass"] = int(benchmark.get("passed") or 0)
        status_counts["fail"] = int(benchmark.get("failed") or 0)

    total = int(benchmark.get("total") or len(checks) or sum(status_counts.values()))
    score = float(benchmark.get("pass_rate") or benchmark.get("overall_score") or 0.0)
    return {
        "pass": status_counts["pass"],
        "fail": status_counts["fail"],
        "error": status_counts["error"],
        "not_applicable": status_counts["not_applicable"],
        "total": total,
        "score": round(score, 1),
    }


def _empty_aisvs_benchmark() -> dict[str, Any]:
    return {
        "benchmark": "OWASP AI Security Verification Standard",
        "benchmark_version": "1.0",
        "passed": 0,
        "failed": 0,
        "total": 0,
        "pass_rate": 0.0,
        "checks": [],
        "metadata": {},
    }


def _build_aisvs_payload(
    benchmark: dict[str, Any] | None,
    *,
    scan_id: str | None = None,
    measured_at: str | None = None,
) -> dict[str, Any]:
    normalized = _empty_aisvs_benchmark()
    if isinstance(benchmark, dict):
        normalized.update(benchmark)
        if not isinstance(normalized.get("checks"), list):
            normalized["checks"] = []
        if not isinstance(normalized.get("metadata"), dict):
            normalized["metadata"] = {}

    summary = _aisvs_summary(normalized)
    return {
        "framework": "aisvs",
        "framework_key": "aisvs_benchmark",
        "framework_label": normalized.get("benchmark") or "OWASP AI Security Verification Standard",
        "source": "scan_jobs",
        "scan_id": scan_id,
        "measured_at": measured_at,
        "summary": summary,
        "score": summary["score"],
        "representation": "benchmark",
        "benchmark": normalized,
    }


def _result_has_runtime_signals(result: dict[str, Any]) -> bool:
    return bool(
        result.get("runtime_correlation")
        or result.get("runtime_session_graph")
        or result.get("introspection")
        or result.get("introspection_data")
        or result.get("health_check")
        or result.get("health_check_data")
    )


def _result_compliance_evidence(result: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the canonical unified spine, with blast-radius legacy fallback."""

    findings = [row for row in (result.get("findings") or []) if isinstance(row, dict)]
    if findings:
        return findings
    return [row for row in (result.get("blast_radius") or []) if isinstance(row, dict)]


def _result_evidence_context(result: dict[str, Any]) -> tuple[bool, bool, set[str]]:
    """Derive MCP and agent context once from canonical scan evidence."""

    sources = {str(source) for source in result.get("scan_sources", []) if source}
    evidence = _result_compliance_evidence(result)
    has_mcp = bool(result.get("has_mcp_context")) or any(row.get("affected_servers") or row.get("owasp_mcp_tags") for row in evidence)
    has_agent = bool(result.get("has_agent_context")) or any(
        row.get("affected_agents") or row.get("owasp_agentic_tags") for row in evidence
    )
    return has_mcp, has_agent, sources


def _aggregate_cis_foundations_checks(jobs: list[Any]) -> dict[str, Any]:
    """Deduped CIS Foundations Benchmark status rollup across a tenant's scans.

    Reuses ``build_cis_benchmark_check_rows`` + the same latest-per-(cloud,
    check_id) dedup as ``/v1/cis/checks`` so the scorecard's benchmark line
    reconciles with that endpoint by construction.

    This is the CIS *Foundations Benchmark* taxonomy (``CIS-2.1.1`` …), a
    different standard from the CVE-driven CIS Controls v8 line (safeguard
    ``CIS-02.1`` …) built elsewhere in :func:`get_compliance`. The two never
    share identifiers, so no control is counted in both lines. Vendor
    best-practice providers (Databricks) are listed by ``/v1/cis/checks`` but
    are not CIS benchmarks, so they are left out here.
    """
    from agent_bom.analytics_contract import VENDOR_BEST_PRACTICE_CLOUDS, build_cis_benchmark_check_rows

    all_rows: list[dict[str, Any]] = []
    for job in jobs:
        if job.status != JobStatus.DONE or not isinstance(getattr(job, "result", None), dict):
            continue
        all_rows.extend(
            build_cis_benchmark_check_rows(
                job.result,
                str(job.result.get("scan_id") or job.job_id),
                measured_at=getattr(job, "completed_at", None) or getattr(job, "created_at", None),
            )
        )
    # Newest measurement per logical (cloud, check_id) wins — identical dedup to
    # the /v1/cis/checks scan_jobs fallback so the two surfaces agree.
    all_rows.sort(key=lambda row: (str(row.get("measured_at") or ""), -int(row.get("priority") or 0)), reverse=True)
    seen: set[tuple[str, str]] = set()
    counts = {"pass": 0, "fail": 0, "error": 0, "not_applicable": 0, "other": 0}
    providers: dict[str, dict[str, int]] = {}
    # Deduped latest status per logical (cloud, check_id) — consumed by the NIST
    # 800-53 catalog line to map a CIS Foundations check to the NIST controls it
    # evidences (framework_mapping.nist_controls_for_cis_check).
    statuses: dict[tuple[str, str], str] = {}
    for row in all_rows:
        key = (str(row.get("cloud") or ""), str(row.get("check_id") or ""))
        if key in seen or key[0] in VENDOR_BEST_PRACTICE_CLOUDS:
            continue
        seen.add(key)
        status = str(row.get("status") or "").lower()
        bucket = status if status in ("pass", "fail", "error", "not_applicable") else "other"
        counts[bucket] += 1
        statuses[key] = status
        cloud = str(row.get("cloud") or "unknown")
        prov = providers.setdefault(cloud, {"pass": 0, "fail": 0, "error": 0, "not_applicable": 0, "other": 0})
        prov[bucket] += 1
    return {"counts": counts, "providers": providers, "total_checks": len(seen), "statuses": statuses}


def _build_cis_foundations_line(agg: dict[str, Any]) -> dict[str, Any]:
    """Shape the benchmark-backed CIS Foundations scorecard line.

    Denominator is honest: ``evaluated = pass + fail + error`` (NOT_APPLICABLE
    checks are excluded from the score). ERROR is an explicit bucket — an
    unevaluable control (permission-denied / unreadable, which the eval layer
    correctly refuses to PASS) is neither pass nor fail, and never inflates the
    numerator.
    """
    counts = agg["counts"]
    passed = int(counts["pass"])
    failed = int(counts["fail"])
    errored = int(counts["error"])
    not_applicable = int(counts["not_applicable"])
    evaluated = passed + failed + errored
    score = round((passed / evaluated) * 100, 1) if evaluated > 0 else 0.0

    if not agg["total_checks"]:
        status = "no_data"
    elif failed > 0:
        status = "fail"
    elif errored > 0:
        # Everything evaluable passed, but some controls were unevaluable — not a
        # clean pass. Surface as warning so the reader knows coverage is partial.
        status = "warning"
    elif evaluated > 0:
        status = "pass"
    else:
        status = "no_data"  # only NOT_APPLICABLE checks — nothing was evaluated

    return {
        "framework": "cis-foundations",
        "framework_key": "cis_foundations_benchmark",
        "framework_label": "CIS Foundations Benchmark",
        "representation": "benchmark",
        "source": "cis_benchmark_data",
        "status": status,
        "score": score,
        "summary": {
            "pass": passed,
            "fail": failed,
            "error": errored,
            "not_applicable": not_applicable,
            "evaluated": evaluated,
            "score": score,
        },
        "providers": agg["providers"],
    }


def _coerce_cis_row(row: dict[str, Any]) -> dict[str, Any]:
    from agent_bom.cloud.cis_remediation import fail_closed_remediation_payload

    coerced = dict(row)
    remediation = coerced.get("remediation")
    if isinstance(remediation, str):
        try:
            remediation = json.loads(remediation)
        except json.JSONDecodeError:
            remediation = {}
    remediation = fail_closed_remediation_payload(
        remediation,
        cloud=str(coerced.get("cloud") or ""),
        benchmark_version=str(coerced.get("benchmark_version") or ""),
        check_id=str(coerced.get("check_id") or ""),
        title=str(coerced.get("title") or ""),
        cis_section=str(coerced.get("cis_section") or ""),
    )
    coerced["remediation"] = remediation
    coerced["fix_cli"] = str(remediation.get("fix_cli") or "")
    coerced["fix_console"] = str(remediation.get("fix_console") or coerced.get("fix_console") or "")
    coerced["effort"] = str(remediation.get("effort") or "manual")
    coerced["requires_human_review"] = True
    return coerced


def _bucket_for(measured_at_iso: str, unit: str) -> str:
    """Truncate ``measured_at_iso`` to the given bucket granularity for the in-memory fallback."""
    if not measured_at_iso:
        return ""
    try:
        moment = datetime.fromisoformat(measured_at_iso.replace("Z", "+00:00"))
    except ValueError:
        return measured_at_iso
    if unit == "hour":
        moment = moment.replace(minute=0, second=0, microsecond=0)
    elif unit == "week":
        moment = moment - timedelta(days=moment.weekday())
        moment = moment.replace(hour=0, minute=0, second=0, microsecond=0)
    else:
        moment = moment.replace(hour=0, minute=0, second=0, microsecond=0)
    return moment.isoformat()


def _narrative_to_dict(narrative: "ComplianceNarrative", *, evidence: dict[str, Any] | None = None) -> dict:
    """Serialise a ComplianceNarrative dataclass to a JSON-safe dict."""
    payload: dict[str, Any] = {
        "executive_summary": narrative.executive_summary,
        "risk_narrative": narrative.risk_narrative,
        "generated_at": narrative.generated_at,
        "claim_boundary": narrative.claim_boundary,
        "framework_narratives": [
            {
                "framework": fn.framework,
                "slug": fn.slug,
                "status": fn.status,
                "score": fn.score,
                "narrative": fn.narrative,
                "recommendations": fn.recommendations,
                "failing_controls": [
                    {
                        "control_id": cn.control_id,
                        "title": cn.title,
                        "status": cn.status,
                        "narrative": cn.narrative,
                        "affected_packages": cn.affected_packages,
                        "affected_agents": cn.affected_agents,
                        "affected_findings": cn.affected_findings,
                        "remediation_steps": cn.remediation_steps,
                    }
                    for cn in fn.failing_controls
                ],
            }
            for fn in narrative.framework_narratives
        ],
        "remediation_impact": [
            {
                "package": ri.package,
                "current_version": ri.current_version,
                "fix_version": ri.fix_version,
                "controls_fixed": ri.controls_fixed,
                "frameworks_impacted": ri.frameworks_impacted,
                "narrative": ri.narrative,
            }
            for ri in narrative.remediation_impact
        ],
    }
    if evidence is not None:
        payload["evidence_snapshot"] = {
            "schema_version": evidence.get("schema_version"),
            "source": "scan_and_current_ingest_findings",
            "tenant_id": evidence.get("tenant_id"),
            "scan_ids": evidence.get("scan_ids", []),
            "completed_scan_count": evidence.get("completed_scan_count", 0),
            "returned": evidence.get("count", 0),
            "total": evidence.get("total"),
            "completeness": evidence.get("completeness"),
            "count_metadata": evidence.get("count_metadata", {}),
            "warnings": evidence.get("warnings", []),
        }
    return payload


def _cis_check_rows_from_jobs(
    jobs: list[Any],
    cloud_filter: set[str],
    status_filter: set[str],
    priority: int | None,
    safe_limit: int,
    safe_offset: int,
) -> dict[str, Any]:
    """Latest CIS check per (cloud, check_id) rebuilt from completed scan jobs."""
    from agent_bom.analytics_contract import build_cis_benchmark_check_rows

    all_rows: list[dict[str, Any]] = []
    for job in jobs:
        if job.status != JobStatus.DONE or not isinstance(getattr(job, "result", None), dict):
            continue
        all_rows.extend(
            build_cis_benchmark_check_rows(
                job.result,
                str(job.result.get("scan_id") or job.job_id),
                measured_at=getattr(job, "completed_at", None) or getattr(job, "created_at", None),
            )
        )
    filtered = [
        row
        for row in all_rows
        if (not cloud_filter or row["cloud"].lower() in cloud_filter)
        and (not status_filter or row["status"].lower() in status_filter)
        and (priority is None or int(row["priority"]) == priority)
    ]
    filtered.sort(key=lambda row: (str(row.get("measured_at") or ""), -int(row.get("priority") or 0)), reverse=True)
    # Collapse to the latest measurement per logical (cloud, check_id) so this
    # in-memory fallback matches the columnar store's DISTINCT ON dedup: without
    # it, N scans of the same cloud would stack N copies of each check. Rows are
    # already sorted newest-first, so the first occurrence wins.
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for row in filtered:
        key = (str(row.get("cloud") or ""), str(row.get("check_id") or ""))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return {"checks": deduped[safe_offset : safe_offset + safe_limit], "count": len(deduped), "source": "scan_jobs"}


def _cis_trend_buckets_from_jobs(
    jobs: list[Any],
    days_clamped: int,
    bucket_unit: str,
    cloud: str | None,
    section: str | None,
    status: str | None,
    severity: str | None,
) -> dict[str, Any]:
    """Time-bucketed CIS check counts rebuilt from the tenant's recent scan jobs."""
    from agent_bom.analytics_contract import build_cis_benchmark_check_rows

    cutoff_isoformat = (datetime.now(timezone.utc) - timedelta(days=days_clamped)).isoformat()
    counts: dict[tuple[str, str, str, str, str], int] = {}
    for job in jobs:
        if job.status != JobStatus.DONE or not isinstance(getattr(job, "result", None), dict):
            continue
        measured_at = getattr(job, "completed_at", None) or getattr(job, "created_at", None)
        if measured_at and str(measured_at) < cutoff_isoformat:
            continue
        rows = build_cis_benchmark_check_rows(
            job.result,
            str(job.result.get("scan_id") or job.job_id),
            measured_at=measured_at,
        )
        for row in rows:
            if cloud and row.get("cloud", "").lower() != cloud.lower():
                continue
            if section and row.get("cis_section", "") != section:
                continue
            if status and row.get("status", "").lower() != status.lower():
                continue
            if severity and row.get("severity", "").lower() != severity.lower():
                continue
            bucket_key = _bucket_for(str(row.get("measured_at") or ""), bucket_unit)
            key = (
                bucket_key,
                row.get("cloud", ""),
                row.get("cis_section", ""),
                row.get("status", ""),
                row.get("severity", ""),
            )
            counts[key] = counts.get(key, 0) + 1

    buckets_payload = [
        {
            "bucket": bucket_value,
            "cloud": cloud_value,
            "cis_section": section_value,
            "status": status_value,
            "severity": severity_value,
            "count": count,
        }
        for (bucket_value, cloud_value, section_value, status_value, severity_value), count in sorted(counts.items(), reverse=True)
    ]
    return {
        "buckets": buckets_payload,
        "count": len(buckets_payload),
        "source": "scan_jobs",
        "bucket": bucket_unit,
        "days": days_clamped,
    }
