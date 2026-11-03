"""Scan progress SSE follows durable job state when another replica owns the job."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.store import SQLiteJobStore

STEP = json.dumps({"type": "step", "step_id": "discovery", "status": "done", "message": "found 3 agents"})


def _job(job_id: str, status: JobStatus, progress: list[str]) -> ScanJob:
    return ScanJob(
        job_id=job_id, tenant_id="default", status=status, created_at="2026-11-01T00:00:00Z", request=ScanRequest(), progress=progress
    )


@pytest.fixture()
def replica_store(tmp_path: Path) -> Iterator[SQLiteJobStore]:
    """A durable store shared with 'replica A'; this process plays replica B."""
    from agent_bom.api import scan_progress_stream
    from agent_bom.api import stores as api_stores

    original = api_stores._store
    store = SQLiteJobStore(str(tmp_path / "jobs.db"))
    api_stores._store = store
    try:
        with (
            patch.object(scan_progress_stream, "DURABLE_POLL_SECONDS", 0.01),
            patch.object(scan_progress_stream, "LOCAL_POLL_SECONDS", 0.01),
        ):
            yield store
    finally:
        api_stores._store = original


def _events(body: str) -> list[dict[str, Any]]:
    return [json.loads(line[len("data: ") :]) for line in body.splitlines() if line.startswith("data: ")]


async def _stream(job_id: str, during: Any = None) -> tuple[int, list[dict[str, Any]]]:
    import httpx

    from agent_bom.api.server import app

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test", timeout=30) as client:
        side = asyncio.create_task(during()) if during else None
        response = await asyncio.wait_for(client.get(f"/v1/scan/{job_id}/stream"), timeout=30)
        if side:
            await side
    return response.status_code, _events(response.text)


async def _until(predicate: Any) -> None:
    for _ in range(2000):
        if predicate():
            return
        await asyncio.sleep(0.005)
    raise AssertionError("condition never held")


@pytest.mark.asyncio
async def test_non_owning_replica_streams_durable_progress_then_done(replica_store: SQLiteJobStore) -> None:
    from agent_bom.api.stores import _jobs_get

    job_id = "replica-a-job"
    replica_store.put(_job(job_id, JobStatus.RUNNING, ["queued on replica A"]))
    assert _jobs_get(job_id, tenant_id="default") is None
    reads: list[str] = []
    real = replica_store.get_status_view

    def counted(*args: Any, **kwargs: Any) -> Any:
        reads.append(args[0])
        return real(*args, **kwargs)

    async def replica_a_finishes() -> None:
        await _until(lambda: len(reads) >= 2)
        replica_store.put(_job(job_id, JobStatus.RUNNING, ["queued on replica A", STEP]))
        count = len(reads)
        await _until(lambda: len(reads) >= count + 2)
        replica_store.put(_job(job_id, JobStatus.DONE, ["queued on replica A", STEP, "Scan complete"]))

    with (
        patch.object(replica_store, "get_status_view", side_effect=counted),
        patch.object(replica_store, "get", wraps=replica_store.get) as full_get,
    ):
        status, events = await _stream(job_id, replica_a_finishes)
    assert status == 200
    assert events == [
        {"type": "progress", "message": "queued on replica A"},
        json.loads(STEP),
        {"type": "progress", "message": "Scan complete"},
        {"type": "done", "status": "done", "job_id": job_id},
    ]
    assert full_get.call_count <= 1, "polling must use the result-free status view, not full job reads"


@pytest.mark.asyncio
@pytest.mark.parametrize("terminal", [JobStatus.FAILED, JobStatus.CANCELLED])
async def test_durable_terminal_state_always_ends_with_done(replica_store: SQLiteJobStore, terminal: JobStatus) -> None:
    replica_store.put(_job("finished-elsewhere", terminal, ["started", "stopped"]))
    status, events = await _stream("finished-elsewhere")
    assert status == 200
    assert events[-1] == {"type": "done", "status": terminal.value, "job_id": "finished-elsewhere"}
    assert [event["message"] for event in events[:-1]] == ["started", "stopped"]


@pytest.mark.asyncio
async def test_durable_progress_is_redacted_like_the_local_stream(replica_store: SQLiteJobStore) -> None:
    secret = "ghp_" + "d" * 36
    replica_store.put(_job("secret-progress", JobStatus.DONE, [f"cloned with {secret}"]))
    _, events = await _stream("secret-progress")
    assert secret not in json.dumps(events)
    assert events[-1]["type"] == "done"


@pytest.mark.asyncio
async def test_stream_ends_when_the_durable_job_is_deleted(replica_store: SQLiteJobStore) -> None:
    replica_store.put(_job("deleted-elsewhere", JobStatus.RUNNING, ["started"]))

    async def replica_a_deletes() -> None:
        await asyncio.sleep(0.05)
        replica_store.delete("deleted-elsewhere", tenant_id="default")

    status, events = await _stream("deleted-elsewhere", replica_a_deletes)
    assert status == 200
    assert events == [{"type": "progress", "message": "started"}]


@pytest.mark.asyncio
async def test_stream_stops_at_the_max_duration(replica_store: SQLiteJobStore) -> None:
    from agent_bom.api import scan_progress_stream

    replica_store.put(_job("never-finishes", JobStatus.RUNNING, ["started"]))
    with patch.object(scan_progress_stream, "STREAM_MAX_SECONDS", 0.1):
        status, events = await _stream("never-finishes")
    assert status == 200
    assert events == [{"type": "progress", "message": "started"}]


@pytest.mark.asyncio
async def test_other_tenants_durable_job_is_not_streamed(replica_store: SQLiteJobStore) -> None:
    replica_store.put(
        ScanJob(job_id="foreign", tenant_id="tenant-b", status=JobStatus.DONE, created_at="2026-11-01T00:00:00Z", request=ScanRequest())
    )
    status, _ = await _stream("foreign")
    assert status == 404


@pytest.mark.asyncio
async def test_local_in_process_job_still_streams_without_durable_polls(replica_store: SQLiteJobStore) -> None:
    from agent_bom.api.stores import _job_lock, _jobs_pop, _jobs_put

    job = _job("local-job", JobStatus.RUNNING, ["started locally"])
    replica_store.put(job)
    _jobs_put(job.job_id, job)

    async def worker_finishes() -> None:
        await asyncio.sleep(0.05)
        with _job_lock(job.job_id):
            job.progress.append("finished locally")
            job.status = JobStatus.DONE

    try:
        with patch.object(replica_store, "get_status_view", side_effect=AssertionError("local jobs must not poll the store")):
            status, events = await _stream(job.job_id, worker_finishes)
    finally:
        _jobs_pop(job.job_id, tenant_id="default")
    assert status == 200
    assert events == [
        {"type": "progress", "message": "started locally"},
        {"type": "progress", "message": "finished locally"},
        {"type": "done", "status": "done", "job_id": job.job_id},
    ]
