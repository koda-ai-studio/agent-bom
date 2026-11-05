"""Real Postgres: an admitted async push is enqueued atomically and ingested once by any replica."""

from __future__ import annotations

import os
from uuid import uuid4

import pytest

from agent_bom.api import pipeline, push_ingest, push_ingest_worker, stores
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.postgres_common import _new_application_pool, reset_current_tenant, set_current_tenant
from agent_bom.api.postgres_job_store import PostgresJobStore

pytestmark = pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires private Postgres")


@pytest.fixture
def pg_store(monkeypatch: pytest.MonkeyPatch):
    pool = _new_application_pool(min_size=1, max_size=4)
    store = PostgresJobStore(pool)
    original = stores._get_store()
    stores.set_job_store(store)
    monkeypatch.setattr(push_ingest, "distributed_scans_enabled", lambda: True)
    monkeypatch.setattr(push_ingest, "enforce_retained_jobs_quota", lambda _tenant: None)
    monkeypatch.setattr(push_ingest, "audit_push_admission", lambda *_args, **_kwargs: None)
    try:
        yield store
    finally:
        stores.set_job_store(original)
        pool.close()


def test_async_push_is_enqueued_with_its_row_and_ingested_once_across_replicas(pg_store, monkeypatch: pytest.MonkeyPatch) -> None:
    graph_calls: list[str] = []

    def _persist(job, report, **_kwargs) -> None:  # noqa: ANN001
        graph_calls.append(job.job_id)
        report["graph_persistence"] = {"status": "persisted", "scan_id": job.job_id}

    monkeypatch.setattr(push_ingest_worker, "_persist_push_graph", _persist)
    monkeypatch.setattr(push_ingest_worker, "_graph_snapshot_exists", lambda _tenant, _scan: False)
    monkeypatch.setattr(push_ingest_worker, "_record_push_trend", lambda *_args, **_kwargs: None)
    tenant, job_id = f"tenant-{uuid4().hex[:12]}", uuid4().hex
    token = set_current_tenant(tenant)
    try:
        job = ScanJob(job_id=job_id, tenant_id=tenant, source_id="host", created_at="2026-11-02T00:00:00Z", request=ScanRequest())
        push_ingest.admit_pushed_job(job, {"pushed": True, "scan_id": job_id, "agents": []}, actor="test", request_hash="h")
        queued = pg_store.get(job_id, tenant_id=tenant)
        assert queued is not None and queued.status is JobStatus.PENDING
    finally:
        reset_current_tenant(token)

    # Replica B claims from the shared queue; replica C finds nothing to steal.
    claimed = pg_store.claim_next("replica-b", 600)
    assert claimed is not None and claimed.job_id == job_id
    assert PostgresJobStore(pg_store._pool).claim_next("replica-c", 600) is None
    from datetime import datetime, timezone

    from agent_bom.api.scan_job_reconciliation import fail_stale_active_scan_jobs

    monkeypatch.setenv("AGENT_BOM_DISTRIBUTED_SCANS", "1")
    # The original admission is old, but the live claim must survive the reaper.
    assert fail_stale_active_scan_jobs(pg_store, timeout_seconds=1, now=datetime(2030, 1, 1, tzinfo=timezone.utc)) == 0
    old_owner = claimed._dispatch_claim_owner
    with pg_store._scope_connection(all_tenants=True) as conn:
        conn.execute("UPDATE scan_dispatch_queue SET lease_expires_at='2000-01-01T00:00:00Z' WHERE job_id=%s", (job_id,))
        conn.commit()
    assert pg_store.requeue_expired_leases() == 1
    claimed = PostgresJobStore(pg_store._pool).claim_next("replica-c", 600)
    assert claimed is not None and claimed.job_id == job_id
    assert claimed._dispatch_claim_owner != old_owner
    token = set_current_tenant(tenant)
    try:
        pipeline._run_claimed_scan_sync(claimed)
        pipeline._run_claimed_scan_sync(claimed)  # redelivery after completion is a no-op
        done = pg_store.get(job_id, tenant_id=tenant)
        assert done is not None and done.status is JobStatus.DONE
        assert graph_calls == [job_id]
        pg_store.complete_dispatch(job_id, tenant_id=tenant, claim_owner=claimed._dispatch_claim_owner or "")
        pg_store.delete(job_id, tenant_id=tenant)
    finally:
        reset_current_tenant(token)
