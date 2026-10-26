"""Sectioned, paged reads of one completed scan result.

``GET /v1/scan/{id}`` returns the whole AI-BOM document. These views return a
small summary plus an index of the large sections, and one section at a time,
paged when it is a list. Each section is redacted exactly as the full-result
endpoint redacts it, so a client paging every section sees the same content.
Callers run these functions in a worker thread: they decode and redact.
"""

from __future__ import annotations

from typing import Any

from agent_bom.api.models import ScanJob
from agent_bom.api.scan_job_views import _redact_scan_result_for_response

SCHEMA_VERSION = "1"
DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 1000
# Small object sections that belong in the summary rather than the index.
SUMMARY_OBJECT_KEYS = frozenset(
    {
        "summary",
        "finding_summary",
        "scan_run",
        "scorecard_summary",
        "posture_scorecard",
        "vuln_data_freshness",
        "scan_performance",
        "framework_catalogs",
    }
)


def _is_summary_key(key: str, value: Any) -> bool:
    return not isinstance(value, dict | list) or key in SUMMARY_OBJECT_KEYS


def _href(job_id: str, name: str, kind: str) -> str:
    base = f"/v1/scan/{job_id}/result/{name}"
    return f"{base}?offset=0&limit={DEFAULT_PAGE_SIZE}" if kind == "list" else base


def result_index(job: ScanJob) -> dict[str, Any]:
    """Summary values plus a reference to every large section."""
    result = job.result or {}
    summary = {key: value for key, value in result.items() if _is_summary_key(key, value)}
    sections = []
    for key, value in result.items():
        if _is_summary_key(key, value):
            continue
        kind = "list" if isinstance(value, list) else "object"
        sections.append({"name": key, "kind": kind, "count": len(value) if kind == "list" else None, "href": _href(job.job_id, key, kind)})
    return {
        "schema_version": SCHEMA_VERSION,
        "job_id": job.job_id,
        "status": job.status.value,
        "result_format": job.result_format,
        "summary": _redact_scan_result_for_response(summary) or {},
        "sections": sections,
    }


def result_section(job: ScanJob, name: str, offset: int, limit: int) -> dict[str, Any]:
    """One section; lists are sliced to ``[offset, offset + limit)``. Raises ``KeyError``."""
    result = job.result or {}
    if name not in result or _is_summary_key(name, result[name]):
        raise KeyError(name)
    value = result[name]
    page: dict[str, Any] = {"schema_version": SCHEMA_VERSION, "job_id": job.job_id, "section": name, "offset": offset}
    if isinstance(value, list):
        window = value[offset : offset + limit]
        redacted = (_redact_scan_result_for_response({name: window}) or {}).get(name, [])
        end = offset + len(window)
        return {
            **page,
            "kind": "list",
            "total": len(value),
            "limit": limit,
            "next_offset": end if end < len(value) else None,
            "items": redacted,
            "value": None,
        }
    redacted_value = (_redact_scan_result_for_response({name: value}) or {}).get(name)
    return {**page, "kind": "object", "total": None, "limit": None, "next_offset": None, "items": None, "value": redacted_value}
