"""Scan progress events for ``GET /v1/scan/{job_id}/stream``.

A job submitted to one replica may run on another (distributed dispatch), so
the in-process ``_jobs`` cache is only a fast path. When the job is not hot in
this process the stream polls the durable job store's result-free status view
off the event loop, emits each progress line once (by index) and always ends
with a ``done`` event once the durable status is terminal. sse-starlette sends
keep-alive pings; ``STREAM_MAX_SECONDS`` bounds the connection.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import AsyncIterator
from typing import Any

from agent_bom.api.models import JobStatus
from agent_bom.api.storage.job_detail_reads import status_view_from_job
from agent_bom.api.stores import _get_store, _job_lock, _jobs_get

_logger = logging.getLogger(__name__)

# Exceeds the stuck-job timeout so a live job is never cut off before it settles.
STREAM_MAX_SECONDS = 2100.0
LOCAL_POLL_SECONDS = 0.25
DURABLE_POLL_SECONDS = 1.0
_TERMINAL = frozenset({JobStatus.DONE, JobStatus.FAILED, JobStatus.CANCELLED})


def _progress_event(line: str) -> dict[str, str]:
    from agent_bom.security import sanitize_sensitive_payload

    try:
        parsed = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        parsed = None
    if isinstance(parsed, dict) and parsed.get("type") == "step":
        return {"data": json.dumps(sanitize_sensitive_payload(parsed))}
    return {"data": json.dumps({"type": "progress", "message": sanitize_sensitive_payload(line)})}


def _durable_status(job_id: str, tenant_id: str) -> tuple[JobStatus, list[str]] | None:
    """Tenant-scoped lifecycle read that does not decode the stored result."""
    store = _get_store()
    reader = getattr(store, "get_status_view", None)
    if callable(reader):
        view = reader(job_id, tenant_id=tenant_id)
    else:
        job = store.get(job_id, tenant_id=tenant_id)
        view = status_view_from_job(job) if job is not None else None
    if view is None:
        return None
    return JobStatus(view["status"]), list(view.get("progress") or [])


def _local_status(job_id: str, tenant_id: str) -> tuple[JobStatus, list[str]] | None:
    current = _jobs_get(job_id, tenant_id=tenant_id)
    if current is None or current.tenant_id != tenant_id:
        return None
    with _job_lock(job_id):
        return current.status, list(current.progress)


async def scan_progress_events(job_id: str, tenant_id: str) -> AsyncIterator[dict[str, Any]]:
    sent = 0
    deadline = time.monotonic() + STREAM_MAX_SECONDS
    while time.monotonic() < deadline:
        snapshot = _local_status(job_id, tenant_id)
        interval = LOCAL_POLL_SECONDS
        if snapshot is None:
            interval = DURABLE_POLL_SECONDS
            try:
                snapshot = await asyncio.to_thread(_durable_status, job_id, tenant_id)
            except Exception as exc:  # noqa: BLE001 - a transient store error must not kill the stream
                from agent_bom.security import sanitize_error, sanitize_text

                _logger.warning("Scan stream durable read failed for job=%s: %s", job_id, sanitize_text(sanitize_error(exc, generic=True)))
                await asyncio.sleep(interval)
                continue
            if snapshot is None:
                return
        status, progress = snapshot
        for line in progress[sent:]:
            yield _progress_event(line)
        sent = max(sent, len(progress))
        if status in _TERMINAL:
            yield {"data": json.dumps({"type": "done", "status": status, "job_id": job_id})}
            return
        await asyncio.sleep(interval)
