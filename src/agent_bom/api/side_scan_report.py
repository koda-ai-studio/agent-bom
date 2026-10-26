"""Persist a completed side-scan as a tenant-scoped scan job and graph snapshot.

The side-scan's packages and CVEs become a ``side_scan_results`` report section
and go through the same job + graph persistence a scan uses, so ``/v1/graph``,
attack paths and the current estate show the VM's CVEs. Each scanned disk or
image is its own replacement scope: a rescan replaces that target's evidence
and never another VM's.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

import anyio.to_thread

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.pipeline import _now, _persist_graph_snapshot
from agent_bom.api.stores import _get_store, _jobs_put
from agent_bom.cloud.side_scan_inventory import side_scan_record
from agent_bom.models import AIBOMReport
from agent_bom.output import to_json

logger = logging.getLogger(__name__)

_NAMESPACE = uuid.UUID("6f1d2a8e-6b3c-5b8e-9a51-2f0a9c7d4e10")


def side_scan_graph_scan_id(tenant_id: str, execution_id: str) -> str:
    """Deterministic per execution, so a replayed request names the same snapshot."""
    return str(uuid.uuid5(_NAMESPACE, f"{tenant_id}\n{execution_id}"))


def _scope(record: dict[str, Any]) -> str:
    return "cloud-side-scan:" + ":".join(str(record.get(key) or "") for key in ("provider", "account_id", "target_type", "target_id"))


def persist_side_scan_graph(*, tenant_id: str, execution_id: str, records: list[dict[str, Any]]) -> dict[str, Any]:
    """Persist ``records`` and return ``{"status", "scan_id"}``; never raises."""
    if not records or not execution_id:
        return {"status": "skipped", "reason": "no_scan_result"}
    if any(record.get("replayed") for record in records):
        # A replay carries counts only; re-persisting would replace real packages with none.
        return {"status": "skipped", "reason": "replayed_execution", "scan_id": side_scan_graph_scan_id(tenant_id, execution_id)}
    scan_id = side_scan_graph_scan_id(tenant_id, execution_id)
    report = AIBOMReport(agents=[], blast_radii=[], scan_id=scan_id)
    report.side_scan_results_data = records
    report.scan_sources = ["cloud_side_scan", f"cloud:{records[0].get('provider') or 'unknown'}"]
    report_json = to_json(report)
    report_json["scan_scope"] = _scope(records[0])
    now = _now()
    job = ScanJob(
        job_id=scan_id,
        tenant_id=tenant_id,
        created_at=now,
        started_at=now,
        completed_at=now,
        status=JobStatus.DONE,
        request=ScanRequest(),
        result=report_json,
        triggered_by=f"cloud-side-scan/{execution_id}",
    )
    try:
        _get_store().put(job)
        _jobs_put(job.job_id, job, compact_terminal=True)
        _persist_graph_snapshot(job, report_json)
    except Exception:  # noqa: BLE001 — the scan result stays readable; the graph gap is reported
        logger.exception("side-scan graph persistence failed")
        return {"status": "failed", "scan_id": scan_id}
    persisted = (job.result or {}).get("graph_persistence") if isinstance(job.result, dict) else None
    status = persisted.get("status", "persisted") if isinstance(persisted, dict) else "persisted"
    return {"status": status, "scan_id": scan_id}


def side_scan_request_error(body: Any) -> str:
    """Why a REST side-scan request is rejected before any cloud call, or ``""``."""
    if body.provider == "azure" and body.target_type == "image":
        return "Azure managed image side-scan is not supported; scan a managed disk instead."
    if body.provider == "azure" and not str(body.collector_resource_group or "").strip():
        return "Azure Managed Disk side-scan requires 'collector_resource_group' for the in-account collector VM."
    return ""


async def persist_side_scan_graph_async(
    tenant_id: str, execution_id: str, provider: str, results: list[Any], status: str
) -> dict[str, Any]:
    """Project a completed scan's VM packages/CVEs into the tenant graph off the event loop."""
    if status != "scan_complete":
        return {"status": "skipped", "reason": f"execution_{status}"}
    records = [side_scan_record(result, provider=provider) for result in results]
    return await anyio.to_thread.run_sync(lambda: persist_side_scan_graph(tenant_id=tenant_id, execution_id=execution_id, records=records))
