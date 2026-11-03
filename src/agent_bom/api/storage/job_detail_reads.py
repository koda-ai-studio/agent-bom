"""Bounded single-job reads that never decode the stored scan result.

Status polling, progress streams and the default job read only need lifecycle
fields and, for a finished job, the summary projection the codec writes beside
a compressed result. These statements select exactly that, so a 100 MB result
costs neither a full transfer nor a GIL-held parse. Like ``job_read_projections``
the store-bound functions take the store as ``self`` and are attached as
methods by each backend.
"""

from __future__ import annotations

import json
from typing import Any, cast

from agent_bom.api.models import JobStatus, ScanJob
from agent_bom.core.tenancy import require_explicit_tenant_id

STATUS_VIEW_FIELDS = (
    "job_id",
    "tenant_id",
    "status",
    "progress",
    "error",
    "created_at",
    "started_at",
    "completed_at",
    "source_id",
    "triggered_by",
)
_METADATA_SQLITE = "json_remove(data, '$.result', '$.result_document')"
_METADATA_POSTGRES = "(data - 'result' - 'result_document')::text"
SQLITE_STATUS_VIEW_SQL = f"SELECT {_METADATA_SQLITE}, status, completed_at FROM jobs WHERE job_id = ? AND tenant_id = ?"  # nosec B608
POSTGRES_STATUS_VIEW_SQL = f"SELECT {_METADATA_POSTGRES}, status, completed_at FROM scan_jobs WHERE job_id = %s AND team_id = %s"  # nosec B608
SQLITE_DETAIL_SQL = (
    f"SELECT {_METADATA_SQLITE}, json_extract(data, '$.result.summary_projection'), "  # nosec B608
    "json_type(data, '$.result.__abom_codec') FROM jobs WHERE job_id = ? AND tenant_id = ?"
)
POSTGRES_DETAIL_SQL = (
    f"SELECT {_METADATA_POSTGRES}, (data #> '{{result,summary_projection}}')::text, "  # nosec B608
    "jsonb_typeof(data #> '{result,__abom_codec}') FROM scan_jobs WHERE job_id = %s AND team_id = %s"
)


def json_column(row: tuple, index: int, default: str, expected_type: type) -> object:
    """Decode one JSON column of a summary row; a missing or null column yields ``default``."""
    if len(row) <= index:
        return json.loads(default)
    value = row[index]
    if isinstance(value, expected_type):
        return value
    return json.loads(value or default)


def _json_value(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str | bytes) else value


def status_view_from_row(row: tuple[Any, ...]) -> dict[str, Any]:
    """Lifecycle fields of one job row; the indexed ``status`` column is authoritative."""
    metadata, status, completed_at = row
    payload = _json_value(metadata)
    payload = payload if isinstance(payload, dict) else {}
    view = {key: payload.get(key) for key in STATUS_VIEW_FIELDS}
    progress = view["progress"]
    view["progress"] = [str(line) for line in progress] if isinstance(progress, list) else []
    view["status"] = JobStatus(status).value
    view["completed_at"] = completed_at
    return view


def status_view_from_job(job: ScanJob) -> dict[str, Any]:
    view = {key: getattr(job, key, None) for key in STATUS_VIEW_FIELDS}
    view["status"] = job.status.value
    view["progress"] = list(job.progress)
    return view


def detail_from_row(row: tuple[Any, ...]) -> tuple[ScanJob, dict[str, Any]] | None:
    """Job metadata plus the stored summary projection; ``None`` when the row has no projection."""
    metadata, projection, codec_type = row
    projection = _json_value(projection)
    if codec_type != "object" or not isinstance(projection, dict):
        return None
    payload = _json_value(metadata)
    return ScanJob.model_validate(payload), projection


def _tenant(tenant_id: str | None) -> str:
    """Request-path reads are always tenant scoped; ``None`` fails closed."""
    require_explicit_tenant_id(tenant_id)
    return cast(str, tenant_id)


def _projection_or_full_row(self: Any, row: Any, job_id: str, tenant_id: str) -> tuple[ScanJob, dict[str, Any] | None] | None:
    if row is None:
        return None
    projected = detail_from_row(tuple(row))
    if projected is not None:
        return projected
    job = self.get(job_id, tenant_id=tenant_id)
    return (job, None) if job is not None else None


def _sqlite_row(self: Any, sql: str, params: tuple[Any, ...]) -> Any:
    try:
        return self._conn.execute(sql, params).fetchone()
    finally:
        self._shrink_connection_memory()
        self._close_thread_connection()


def sqlite_status_view(self: Any, job_id: str, tenant_id: str | None = None) -> dict[str, Any] | None:
    """Lifecycle fields (status, progress, error, timestamps) without decoding the stored result."""
    row = _sqlite_row(self, SQLITE_STATUS_VIEW_SQL, (job_id, _tenant(tenant_id)))
    return status_view_from_row(tuple(row)) if row is not None else None


def sqlite_detail_projection(self: Any, job_id: str, *, tenant_id: str) -> tuple[ScanJob, dict[str, Any] | None] | None:
    """Job metadata plus the stored summary projection; rows without one load whole."""
    row = _sqlite_row(self, SQLITE_DETAIL_SQL, (job_id, _tenant(tenant_id)))
    return _projection_or_full_row(self, row, job_id, tenant_id)


def _postgres_row(self: Any, sql: str, params: tuple[Any, ...]) -> Any:
    with self._scope_connection() as conn:
        return conn.execute(sql, params).fetchone()


def postgres_status_view(self: Any, job_id: str, tenant_id: str | None = None) -> dict[str, Any] | None:
    """Lifecycle fields; the stored result never leaves the database."""
    row = _postgres_row(self, POSTGRES_STATUS_VIEW_SQL, (job_id, _tenant(tenant_id)))
    return status_view_from_row(tuple(row)) if row is not None else None


def postgres_detail_projection(self: Any, job_id: str, *, tenant_id: str) -> tuple[ScanJob, dict[str, Any] | None] | None:
    """Job metadata plus the stored summary projection; rows without one load whole."""
    row = _postgres_row(self, POSTGRES_DETAIL_SQL, (job_id, _tenant(tenant_id)))
    return _projection_or_full_row(self, row, job_id, tenant_id)


def memory_status_view(self: Any, job_id: str, tenant_id: str | None = None) -> dict[str, Any] | None:
    """Lifecycle fields only; the in-memory row is never copied whole."""
    key = (_tenant(tenant_id), job_id)
    with self._lock:
        job = self._jobs.get(key)
        return status_view_from_job(job) if job is not None else None


def status_view_from_full_read(self: Any, job_id: str, tenant_id: str | None = None) -> dict[str, Any] | None:
    """Fallback for backends without a result-free projection: reads the whole row."""
    job = self.get(job_id, tenant_id=_tenant(tenant_id))
    return status_view_from_job(job) if job is not None else None
