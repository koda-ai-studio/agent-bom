"""Runtime evidence and side-scan result projections."""

from __future__ import annotations

from typing import Any, cast

from agent_bom.api.cloud_response_helpers import _logger
from agent_bom.api.models import ScanJob
from agent_bom.canonical_ids import canonical_id
from agent_bom.cloud.runtime_workload_evidence import RuntimeWorkloadSignal
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.types import EntityType
from agent_bom.security import sanitize_sensitive_payload


def _runtime_cohort_graph(*, scan_id: str, tenant_id: str, created_at: str, signals: list[RuntimeWorkloadSignal]) -> UnifiedGraph:
    """Project accepted runtime observations into an exact-identity snapshot."""

    graph = UnifiedGraph(scan_id=scan_id, tenant_id=tenant_id, created_at=created_at)
    for signal in signals:
        stable_id = canonical_id("cloud_resource", signal.provider, signal.account_id, signal.workload_ref)
        graph.add_node(
            UnifiedNode(
                id=f"cloud_resource:runtime:{stable_id}",
                entity_type=EntityType.CLOUD_RESOURCE,
                label=signal.workload_ref,
                risk_score=float({"critical": 100, "high": 80, "medium": 50, "low": 20}.get(signal.severity, 0)),
                severity=signal.severity,
                first_seen=signal.observed_at,
                last_seen=signal.observed_at,
                attributes={
                    "canonical_id": stable_id,
                    "resource_id": signal.workload_ref,
                    "resource_type": "workload_disk",
                    "cloud_provider": signal.provider,
                    "cloud_account_id": signal.account_id,
                    "account_id": signal.account_id,
                    "runtime_id": signal.workload_id,
                    "runtime_observed": True,
                    "runtime_evidence": signal.to_dict(),
                },
                data_sources=[f"runtime:{signal.source_id}"],
                dimensions=NodeDimensions(cloud_provider=signal.provider, surface="runtime"),
            )
        )
    return graph


def _runtime_cohort_response(child: ScanJob) -> dict[str, Any]:
    result = child.result if isinstance(child.result, dict) else {}
    summary = result.get("runtime_evidence_ingest")
    response = dict(summary) if isinstance(summary, dict) else {}
    response.update(
        {
            "job_id": child.job_id,
            "correlation_cohort_id": child.correlation_cohort_id or "",
            "cohort_manifest_hash": child.correlation_cohort_manifest_hash or "",
            "status": "stored",
        }
    )
    return response


_SIDESCAN_PROVIDERS = ("azure", "gcp")


def _run_provider_side_scan_sync(**kwargs: Any) -> list[Any]:
    """Drive one Azure/GCP side-scan to completion on a fresh loop in a worker thread.

    Kept module-level so the offload seam is spy-able/patch-able in tests and so
    the coroutine never touches the request event loop. ``run_provider_side_scan``
    attempts teardown of owned temporary resources and records incomplete cleanup.
    """
    import asyncio

    from agent_bom.cloud.side_scan_targets import run_provider_side_scan

    return asyncio.run(run_provider_side_scan(**kwargs))


def _side_scan_result_summary(results: list[Any]) -> dict[str, Any]:
    """Metadata-only run summary (never raw block data, file contents, or values)."""
    if not results:
        return {}
    res = results[0]
    counts = getattr(res, "recorded_counts", None) or {}
    return {
        "target_id": getattr(res, "target_id", ""),
        "snapshot_id": getattr(res, "snapshot_id", None),
        "scan_disk_id": getattr(res, "scan_disk_id", None),
        "package_count": counts.get("package_count", len(getattr(res, "packages", []) or [])),
        "vulnerability_count": counts.get("vulnerability_count", int(getattr(res, "vulnerability_count", 0) or 0)),
        "secret_count": counts.get("secret_count", len(getattr(res, "secrets", []) or [])),
        "config_finding_count": counts.get("config_finding_count", len(getattr(res, "config_findings", []) or [])),
        "ioc_finding_count": counts.get("ioc_finding_count", len(getattr(res, "ioc_findings", []) or [])),
        "cleaned_up": bool(getattr(res, "cleaned_up", False)),
        "replayed": bool(getattr(res, "replayed", False)),
        "warnings": [str(w) for w in (getattr(res, "warnings", []) or [])],
    }


def _run_cis_benchmark(
    tenant_id: str,
    requested: str,
    check_list: list[str] | None,
    region_arg: str | None,
    profile_arg: str | None,
    subscription_id: str,
    project_id: str,
) -> dict[str, Any]:
    """Synchronous CIS benchmark body — runs off the event loop in a worker thread.

    Calls the same provider ``run_benchmark`` functions the CLI/MCP use and
    returns the report's canonical ``to_dict()`` shape unchanged. A missing SDK /
    credentials degrades to the HTTP-200 ``unavailable`` envelope exactly as
    before. Kept module-level so the offload seam is spy-able and testable.
    """
    from agent_bom.cloud import CloudDiscoveryError

    report: Any
    try:
        if requested == "aws":
            if region_arg:
                from agent_bom.cloud.aws_cis_benchmark import run_benchmark

                report = run_benchmark(region=region_arg, profile=profile_arg, checks=check_list)
            else:
                from agent_bom.cloud.aws_cis_benchmark import run_benchmark_all_regions

                report = run_benchmark_all_regions(region=region_arg, profile=profile_arg, checks=check_list)
        elif requested == "azure":
            from agent_bom.cloud.azure_cis_benchmark import run_benchmark as run_azure_cis

            report = run_azure_cis(subscription_id=subscription_id.strip() or None, checks=check_list)
        elif requested == "snowflake":
            from agent_bom.cloud.snowflake_cis_benchmark import run_benchmark as run_snowflake_cis

            # Snowflake uses the same account credentials as CLI/MCP.
            report = run_snowflake_cis(checks=check_list)
        elif requested == "databricks":
            from agent_bom.cloud.databricks_security import run_security_checks

            report = run_security_checks(checks=check_list)
        else:  # gcp
            from agent_bom.cloud.gcp_cis_benchmark import run_benchmark as run_gcp_cis

            report = run_gcp_cis(project_id=project_id.strip() or None, checks=check_list)
    except CloudDiscoveryError:
        # Provider SDK absent / credentials unavailable degrades to a clear
        # error envelope (HTTP 200) — exactly as the MCP cis_benchmark tool
        # does — never a 500. Keeps REST / MCP shape parity for the no-SDK path.
        # Log only a canonical allowlisted provider label — a literal chosen by
        # comparison, never the user string or the exception (avoids log injection
        # + exception-detail exposure; CR/LF strip alone isn't a recognized barrier).
        provider_label = _cis_provider_label(requested)
        _logger.warning("Cloud CIS benchmark unavailable for %s", provider_label)
        return {
            "error": "Provider SDK or credentials unavailable for this benchmark.",
            "provider": requested,
            "tenant_id": tenant_id,
            "status": "unavailable",
        }

    sanitized_result = sanitize_sensitive_payload(report.to_dict())
    if not isinstance(sanitized_result, dict):  # pragma: no cover - report contracts return mappings
        raise TypeError("Provider benchmark report must be a mapping")
    result = cast(dict[str, Any], sanitized_result)
    result.setdefault("tenant_id", tenant_id)
    result["audit_metadata"] = {
        "read_only": True,
        "writes_performed": False,
        "provider": requested,
        "note": "Benchmark checks are read-only; evaluate provider posture without mutating resources.",
    }
    return result


def _cis_provider_label(requested: str) -> str:
    if requested == "aws":
        provider_label = "aws"
    elif requested == "azure":
        provider_label = "azure"
    elif requested == "gcp":
        provider_label = "gcp"
    elif requested == "snowflake":
        provider_label = "snowflake"
    elif requested == "databricks":
        provider_label = "databricks"
    else:
        provider_label = "unknown"
    return provider_label
