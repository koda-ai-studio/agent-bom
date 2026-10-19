"""Connection lifecycle receipts and scan report persistence."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from agent_bom.api.connection_request_validation import _now
from agent_bom.api.connection_store import CloudConnectionRecord, get_connection_store

_MAX_STATUS_DETAIL = 300

if TYPE_CHECKING:
    from agent_bom.api.models import ScanJob


_logger = logging.getLogger("agent_bom.api.routes.cloud_connections")


def _mark_connection(
    record: CloudConnectionRecord,
    *,
    status: str,
    status_detail: str = "",
    capability_probe_status: str | None = None,
    verified_capabilities: list[str] | None = None,
    last_scan_at: str | None = None,
    last_scan_id: str | None = None,
) -> None:
    """Persist a connection lifecycle transition via the Phase A store's upsert.

    Reuses ``put`` (the store's update path) rather than a parallel mutator. The
    record was already fetched tenant-scoped, so this stays within the tenant.
    ``status_detail`` is capped and never carries a secret (the broker's error
    text is secret-free and is additionally sanitized by the caller).
    """
    record.status = status
    record.status_detail = status_detail[:_MAX_STATUS_DETAIL]
    if capability_probe_status is not None:
        record.capability_probe_status = capability_probe_status
    if verified_capabilities is not None:
        record.verified_capabilities = list(verified_capabilities)
    record.updated_at = _now()
    if last_scan_at is not None:
        record.last_scan_at = last_scan_at
    if last_scan_id is not None:
        record.last_scan_id = last_scan_id
    get_connection_store().put(record)


def _safe_connection_detail(exc: Exception) -> str:
    """Actionable, secret-free detail for a failed connection test/scan.

    Thin alias for the shared boundary in
    :func:`agent_bom.cloud.connection_broker.operator_facing_detail`, which the
    CLI uses too — one definition, no drift between surfaces.
    """
    from agent_bom.cloud.connection_broker import operator_facing_detail

    return operator_facing_detail(exc)


def _cis_summary(cis_dict: Mapping[str, Any]) -> dict[str, Any]:
    """Reduce a CIS report dict to the non-secret counts surfaced in the summary."""
    return {
        "benchmark": cis_dict.get("benchmark"),
        "benchmark_version": cis_dict.get("benchmark_version"),
        "scope": cis_dict.get("scope"),
        "completeness": cis_dict.get("completeness"),
        "accounts_scanned": len(cis_dict.get("accounts_scanned") or []),
        "regions_scanned": len(cis_dict.get("regions_scanned") or []),
        "passed": cis_dict.get("passed"),
        "failed": cis_dict.get("failed"),
        "errored": cis_dict.get("errored"),
        "not_applicable": cis_dict.get("not_applicable"),
        "evaluated": cis_dict.get("evaluated"),
        "total": cis_dict.get("total"),
        "pass_rate": cis_dict.get("pass_rate"),
    }


def _annotate_inventory_counts(inventory: Any) -> None:
    """Add UI-facing count fields to a persisted raw inventory payload in place.

    The persisted ``cloud_inventory`` keeps the raw provider resource lists the
    graph builder ingests, but those carry no top-level counts. The Scan-jobs
    pipeline panel and scan-result view read ``resource_count`` / ``identity_count``
    (with a ``node_summary`` fallback), so without these a completed cloud-connection
    scan surfaced empty resource/identity stats. Enrich the payload (non-destructive
    — raw lists are preserved) with the same counts ``_summarize_inventory_payload``
    computes so those stats populate honestly.

    An org-scope scan persists a **list** of per-account payloads; the panel
    sums the per-account counts, so each element is annotated in turn.
    """
    if isinstance(inventory, list):
        for item in inventory:
            _annotate_inventory_counts(item)
        return
    if not isinstance(inventory, dict):
        return
    if "resource_count" in inventory and "identity_count" in inventory:
        return
    from agent_bom.cloud.inventory_summary import _summarize_inventory_payload

    summary = _summarize_inventory_payload(str(inventory.get("provider") or ""), inventory)
    inventory.setdefault("resource_count", summary["resource_count"])
    inventory.setdefault("identity_count", summary["identity_count"])
    inventory.setdefault("node_summary", summary["node_summary"])


def _persist_connection_report(
    record: CloudConnectionRecord,
    tenant_id: str,
    report: Any,
    *,
    queued_job: ScanJob | None = None,
) -> str:
    """Persist a brokered-scan report through the existing scan/graph stores.

    Reuses the pipeline's persistence path (durable scan store + in-memory job
    map + unified graph snapshot) rather than a parallel one — the same calls the
    scan pipeline makes on completion. Returns the scan id.
    """
    from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
    from agent_bom.api.pipeline import _persist_graph_snapshot
    from agent_bom.api.stores import _get_store, _jobs_put
    from agent_bom.output import to_json

    if queued_job is not None:
        report.scan_id = queued_job.job_id
    report_json = to_json(report)
    _annotate_inventory_counts(report_json.get("cloud_inventory"))
    now = _now()
    if queued_job is None:
        scan_job = ScanJob(
            job_id=report.scan_id,
            tenant_id=tenant_id,
            created_at=now,
            started_at=now,
            completed_at=now,
            status=JobStatus.DONE,
            request=ScanRequest(),
            result=report_json,
            triggered_by=f"cloud-connection/{record.id}",
        )
        store = _get_store()
        store.put(scan_job)
        _jobs_put(scan_job.job_id, scan_job, compact_terminal=True)
    else:
        # The durable worker owns lifecycle persistence for queued scans. Reuse
        # the accepted job id so retries/reclaims replace the same artifact
        # instead of minting an orphan result row.
        scan_job = queued_job
        scan_job.result = report_json
    from agent_bom.api.trend_comparison import connection_scope_id
    from agent_bom.api.trend_recording import record_scan_trend_best_effort

    record_scan_trend_best_effort(
        report_json,
        tenant_id=tenant_id,
        scan_id=scan_job.job_id,
        scope_id=connection_scope_id(record),
        completed_at=now,
    )
    _persist_graph_snapshot(scan_job, report_json)
    return str(scan_job.job_id)


def _mark_connection_report_sources(report: Any, provider: str) -> None:
    """Stamp connection-originated scans so downstream UI/compliance do not look local."""
    report.scan_sources = ["cloud_connection", f"cloud:{provider}"]


def _scan_audit_metadata(note: str) -> dict[str, Any]:
    """Read-only audit envelope attached to every connection-scan summary."""
    return {"read_only": True, "writes_performed": False, "note": note}


def _test_connection_broker(record: CloudConnectionRecord) -> Any:
    """Broker credentials and prove a provider-specific read capability.

    This deliberately does not run inventory, CIS, or persistence. Bedrock and
    Vertex onboarding must not become active after credential construction
    alone, so the shared CLI/API capability probe executes one bounded read.
    """

    from agent_bom.cloud.capability_probe import probe_read_capability
    from agent_bom.cloud.connection_broker import broker_session

    brokered = broker_session(record, session_name=f"agent-bom-test-{record.id[:8]}")
    return probe_read_capability(
        (record.provider or "").strip().lower(),
        brokered,
        regions=list(record.regions),
        auth_params=dict(record.auth_params),
    )
