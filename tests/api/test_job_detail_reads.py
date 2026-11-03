"""Result-free job reads: status views and summary projections never decode the stored result."""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from unittest.mock import patch
from uuid import uuid4

import pytest

from agent_bom.api.job_payload_codec import RESULT_CODEC_KEY, RESULT_PROJECTION_KEY, result_summary_projection
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.scan_job_detail import summary_body
from agent_bom.api.store import InMemoryJobStore, SQLiteJobStore

STATUS_KEYS = {
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
}


def _result(findings: int = 400) -> dict[str, Any]:
    return {
        "scan_id": "scan-1",
        "generated_at": "2026-11-01T00:00:00Z",
        "summary": {"total_findings": findings, "total_packages": 3},
        "scan_run": {"outcome": "complete"},
        "aggregation": {"agents": 2},
        "graph_persistence": {"status": "persisted", "scan_id": "scan-1", "nodes": 4, "edges": 5},
        "warnings": [f"warning {i}" for i in range(7)],
        "findings": [{"id": f"f-{i}", "title": "x" * 40} for i in range(findings)],
        "blast_radius": [{"id": i} for i in range(findings // 2)],
        "exposure_paths": {"paths": []},
    }


def _job(tenant: str, status: JobStatus = JobStatus.DONE, **extra: Any) -> ScanJob:
    return ScanJob(
        job_id=extra.pop("job_id", uuid4().hex),
        tenant_id=tenant,
        status=status,
        created_at="2026-11-01T00:00:00Z",
        started_at="2026-11-01T00:00:01Z",
        completed_at="2026-11-01T00:05:00Z" if status == JobStatus.DONE else None,
        triggered_by="api",
        source_id="source-1",
        request=ScanRequest(),
        progress=["one", "two"],
        result=_result() if status == JobStatus.DONE else None,
        **extra,
    )


@contextmanager
def _no_result_decode() -> Iterator[None]:
    def refuse(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("the stored result was decoded")

    with patch("agent_bom.api.job_payload_codec.decode_zstd_json", side_effect=refuse):
        yield


def _assert_status_view(view: dict[str, Any] | None, job: ScanJob) -> None:
    assert view is not None
    assert set(view) >= STATUS_KEYS
    assert view["status"] == job.status.value
    assert view["progress"] == list(job.progress)
    for key in STATUS_KEYS - {"status", "progress"}:
        assert view[key] == getattr(job, key), key


def test_codec_writes_a_summary_projection_beside_a_compressed_result(tmp_path: Path) -> None:
    store = SQLiteJobStore(str(tmp_path / "jobs.db"))
    job = _job("acme")
    store.put(job)
    stored = json.loads(store._conn.execute("SELECT data FROM jobs WHERE job_id = ?", (job.job_id,)).fetchone()[0])["result"]
    assert RESULT_CODEC_KEY in stored
    assert stored[RESULT_PROJECTION_KEY] == result_summary_projection(job.result)
    projection = stored[RESULT_PROJECTION_KEY]
    assert projection["fields"]["warnings"] == job.result["warnings"][:3] and projection["fields"]["warning_total"] == 7
    assert "findings" not in projection["fields"]
    assert ["findings", "list", 400] in projection["shape"]
    assert store.get(job.job_id, tenant_id="acme").model_dump() == job.model_dump()


@pytest.mark.parametrize("status", list(JobStatus))
def test_sqlite_status_view_is_tenant_scoped_and_result_free(tmp_path: Path, status: JobStatus) -> None:
    store = SQLiteJobStore(str(tmp_path / "jobs.db"))
    job = _job("acme", status, error="boom" if status == JobStatus.FAILED else None)
    store.put(job)
    with _no_result_decode():
        _assert_status_view(store.get_status_view(job.job_id, tenant_id="acme"), job)
        assert store.get_status_view(job.job_id, tenant_id="other") is None
        assert store.get_status_view("missing", tenant_id="acme") is None
    with pytest.raises(ValueError):
        store.get_status_view(job.job_id, tenant_id=None)


def test_memory_status_view_is_tenant_scoped() -> None:
    store = InMemoryJobStore()
    job = _job("acme", JobStatus.RUNNING)
    store.put(job)
    _assert_status_view(store.get_status_view(job.job_id, tenant_id="acme"), job)
    assert store.get_status_view(job.job_id, tenant_id="other") is None
    with pytest.raises(ValueError):
        store.get_status_view(job.job_id)


def test_sqlite_detail_projection_matches_the_full_summary_without_decoding(tmp_path: Path) -> None:
    store = SQLiteJobStore(str(tmp_path / "jobs.db"))
    job = _job("acme")
    store.put(job)
    with _no_result_decode():
        found = store.get_detail_projection(job.job_id, tenant_id="acme")
        assert store.get_detail_projection(job.job_id, tenant_id="other") is None
    assert found is not None
    metadata, projection = found
    assert metadata.result is None and metadata.progress == job.progress
    assert projection is not None
    assert summary_body(metadata, projection) == summary_body(job, None)


@pytest.mark.parametrize("codec", ["none", "zstd"])
def test_rows_without_a_projection_fall_back_to_the_full_row(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, codec: str) -> None:
    monkeypatch.setenv("AGENT_BOM_JOB_RESULT_CODEC", codec)
    store = SQLiteJobStore(str(tmp_path / "jobs.db"))
    job = _job("acme")
    store.put(job)
    if codec == "zstd":  # a row written before projections existed
        data = json.loads(store._conn.execute("SELECT data FROM jobs WHERE job_id = ?", (job.job_id,)).fetchone()[0])
        data["result"].pop(RESULT_PROJECTION_KEY)
        store._conn.execute("UPDATE jobs SET data = ? WHERE job_id = ?", (json.dumps(data), job.job_id))
        store._conn.commit()
    found = store.get_detail_projection(job.job_id, tenant_id="acme")
    assert found is not None
    full, projection = found
    assert projection is None and full.result == job.result
    assert summary_body(full, projection) == summary_body(job, None)


def test_running_jobs_project_without_a_result(tmp_path: Path) -> None:
    store = SQLiteJobStore(str(tmp_path / "jobs.db"))
    job = _job("acme", JobStatus.RUNNING)
    store.put(job)
    found = store.get_detail_projection(job.job_id, tenant_id="acme")
    assert found is not None
    body = summary_body(*found)
    assert body["status"] == "running" and body["result_sections"] == [] and body["summary"] is None


@pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires private Postgres")
def test_postgres_status_view_and_projection_are_tenant_scoped_and_result_free() -> None:
    from agent_bom.api.postgres_common import _new_application_pool, reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_job_store import PostgresJobStore

    pool = _new_application_pool(min_size=1, max_size=3)
    owner, other = "detail-" + uuid4().hex, "detail-" + uuid4().hex
    try:
        store = PostgresJobStore(pool)
        job = _job(owner)
        running = _job(owner, JobStatus.RUNNING)
        token = set_current_tenant(owner)
        try:
            store.put(job)
            store.put(running)
            with _no_result_decode():
                _assert_status_view(store.get_status_view(job.job_id, tenant_id=owner), job)
                _assert_status_view(store.get_status_view(running.job_id, tenant_id=owner), running)
                found = store.get_detail_projection(job.job_id, tenant_id=owner)
            assert found is not None and found[0].result is None and found[1] is not None
            assert summary_body(*found) == summary_body(job, None)
            with pytest.raises(ValueError):
                store.get_status_view(job.job_id)
        finally:
            reset_current_tenant(token)
        token = set_current_tenant(other)
        try:
            assert store.get_status_view(job.job_id, tenant_id=other) is None
            assert store.get_detail_projection(job.job_id, tenant_id=other) is None
        finally:
            reset_current_tenant(token)
        token = set_current_tenant(owner)
        try:
            store.delete(job.job_id, tenant_id=owner)
            store.delete(running.job_id, tenant_id=owner)
        finally:
            reset_current_tenant(token)
    finally:
        pool.close()
