"""Bodies for ``GET /v1/scan/{job_id}``: a bounded summary by default, the full job on request.

Both builders return pre-serialized JSON bytes and run in a worker thread, so a
large result is never re-validated against a response model on the event loop.
The summary reads the codec's stored summary projection when the backend
offers one and never decodes the stored result. The full body keeps the
``ScanJob`` serializers (request and progress sanitizers) and the result
redaction of the previous default response.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Literal

from fastapi import Request
from pydantic_core import to_json

from agent_bom.api import scan_request_context
from agent_bom.api.job_payload_codec import result_summary_projection
from agent_bom.api.models import JobStatus, ScanJob
from agent_bom.api.read_models.scan import ScanJobSummaryResponse
from agent_bom.api.scan_job_views import _job_response_payload, _job_summary_payload
from agent_bom.api.scan_result_sections import section_refs
from agent_bom.api.stores import _get_store, _jobs_get, _jobs_is_compacted

ScanJobView = Literal["summary", "full"]
SCAN_JOB_VIEWS: tuple[ScanJobView, ...] = ("summary", "full")
_RECEIPT_TEXT_MAX = 200

SCAN_JOB_DETAIL_RESPONSES: dict[int | str, dict[str, Any]] = {
    200: {
        "model": ScanJobSummaryResponse | ScanJob,
        "description": "``view=summary`` (default) returns ScanJobSummaryResponse; ``view=full`` returns ScanJob.",
    }
}


def _graph_receipt(value: Any) -> dict[str, Any] | None:
    """Bounded graph persistence facts; arbitrary stored detail is dropped."""
    from agent_bom.security import sanitize_text

    if not isinstance(value, Mapping):
        return None
    receipt: dict[str, Any] = {"status": sanitize_text(str(value.get("status") or "unknown"), max_len=_RECEIPT_TEXT_MAX)}
    scan_id = value.get("scan_id")
    if isinstance(scan_id, str) and scan_id:
        receipt["scan_id"] = sanitize_text(scan_id, max_len=_RECEIPT_TEXT_MAX)
    for key in ("nodes", "edges"):
        count = value.get(key)
        if type(count) is int and count >= 0:
            receipt[key] = count
    return receipt


def _links(job_id: str) -> dict[str, str]:
    base = f"/v1/scan/{job_id}"
    return {
        "self": base,
        "full": f"{base}?view=full",
        "status": f"{base}/status",
        "result": f"{base}/result",
        "stream": f"{base}/stream",
    }


def summary_body(job: ScanJob, projection: Mapping[str, Any] | None) -> dict[str, Any]:
    """Status payload plus lifecycle, sanitized progress, graph receipt and section links."""
    from agent_bom.security import sanitize_sensitive_payload

    if projection is None and isinstance(job.result, dict):
        projection = result_summary_projection(job.result)
    fields = projection.get("fields") if isinstance(projection, Mapping) else None
    fields = fields if isinstance(fields, Mapping) else {}
    shape = projection.get("shape") if isinstance(projection, Mapping) else None
    progress = sanitize_sensitive_payload(list(job.progress))
    done = job.status == JobStatus.DONE
    return {
        **_job_summary_payload(job, fields),
        "view": "summary",
        "triggered_by": job.triggered_by,
        "started_at": job.started_at,
        "result_format": job.result_format,
        "progress": progress if isinstance(progress, list) else [],
        "graph_persistence": _graph_receipt(fields.get("graph_persistence")),
        "result_sections": section_refs(job.job_id, shape) if done and isinstance(shape, list) else [],
        "links": _links(job.job_id),
    }


def _summary_source(request: Request, job_id: str) -> tuple[ScanJob, Mapping[str, Any] | None]:
    """Hot in-memory job, else the store's result-free projection, else the full read path."""
    tenant_id = scan_request_context._tenant_id(request)
    hot = _jobs_get(job_id, tenant_id=tenant_id)
    usable_hot = hot is not None and scan_request_context._visible_to_tenant(hot, tenant_id) and not _jobs_is_compacted(hot)
    reader = getattr(_get_store(), "get_detail_projection", None)
    if not usable_hot and callable(reader):
        found = reader(job_id, tenant_id=tenant_id)
        if found is not None and not found[0].child_job_ids:
            return found
    # Hot rows, batch parents and misses keep the shared read path (refresh, 404).
    return scan_request_context._job_for_request(request, job_id), None


def summary_body_for_request(request: Request, job_id: str) -> bytes:
    job, projection = _summary_source(request, job_id)
    return to_json(summary_body(job, projection))


def full_body(job: ScanJob) -> bytes:
    """The redacted job serialized by its own ``ScanJob`` serializers, without re-validation."""
    payload = _job_response_payload(job)
    return payload.__pydantic_serializer__.to_json(payload)
