"""Real Postgres: an admitted async push is enqueued atomically and ingested once by any replica."""

from __future__ import annotations

import os
import threading
import time
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from agent_bom.api import job_read_retry, pipeline, push_ingest, push_ingest_worker, stores
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.postgres_common import _new_application_pool, reset_current_tenant, set_current_tenant
from agent_bom.api.postgres_job_store import PostgresJobStore
from agent_bom.api.scan_queue import DistributedScanWorker

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


_TENANTS: list[str] = []


def _tenant() -> str:
    _TENANTS.append(f"tenant-{uuid4().hex[:12]}")
    return _TENANTS[-1]


@pytest.fixture(autouse=True)
def _remove_test_jobs(pg_store):
    # The queue is global: a row left behind would be the next suite's oldest claim.
    yield
    with pg_store._scope_connection(all_tenants=True) as conn:
        conn.execute("DELETE FROM scan_jobs WHERE team_id = ANY(%s)", (_TENANTS,))
        conn.commit()
    _TENANTS.clear()


def test_async_push_is_enqueued_with_its_row_and_ingested_once_across_replicas(pg_store, monkeypatch: pytest.MonkeyPatch) -> None:
    graph_calls: list[str] = []

    def _persist(job, report, **_kwargs) -> None:  # noqa: ANN001
        graph_calls.append(job.job_id)
        report["graph_persistence"] = {"status": "persisted", "scan_id": job.job_id}

    monkeypatch.setattr(push_ingest_worker, "_persist_push_graph", _persist)
    monkeypatch.setattr(push_ingest_worker, "_graph_snapshot_exists", lambda _tenant, _scan: False)
    monkeypatch.setattr(push_ingest_worker, "_record_push_trend", lambda *_args, **_kwargs: None)
    tenant, job_id = _tenant(), uuid4().hex
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
    from agent_bom.api.scan_job_reconciliation import fail_stale_active_scan_jobs

    monkeypatch.setenv("AGENT_BOM_DISTRIBUTED_SCANS", "1")
    # The original admission is old, but the live claim must survive the reaper.
    fail_stale_active_scan_jobs(pg_store, timeout_seconds=1, now=datetime(2030, 1, 1, tzinfo=timezone.utc))
    assert _job_in(pg_store, tenant, job_id).status is JobStatus.PENDING
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


class _ProcessKilled(BaseException):
    """Unwinds like SIGKILL: no ``except Exception`` compensation runs."""


def _expire_lease(store: PostgresJobStore, tenant: str, job_id: str) -> None:
    with store._scope_connection(all_tenants=True) as conn:
        conn.execute(
            "UPDATE scan_dispatch_queue SET lease_expires_at='2000-01-01T00:00:00Z' WHERE tenant_id=%s AND job_id=%s", (tenant, job_id)
        )
        conn.commit()


def _queue_row(store: PostgresJobStore, tenant: str, job_id: str) -> tuple | None:
    with store._scope_connection(all_tenants=True) as conn:
        return conn.execute(
            "SELECT status, attempts, claimed_by FROM scan_dispatch_queue WHERE tenant_id=%s AND job_id=%s", (tenant, job_id)
        ).fetchone()


def _queue_status(store: PostgresJobStore, tenant: str, job_id: str) -> str | None:
    with store._scope_connection(all_tenants=True) as conn:
        row = conn.execute("SELECT status FROM scan_dispatch_queue WHERE tenant_id=%s AND job_id=%s", (tenant, job_id)).fetchone()
    return row[0] if row else None


def _job_in(store: PostgresJobStore, tenant: str, job_id: str) -> ScanJob | None:
    token = set_current_tenant(tenant)
    try:
        return store.get(job_id, tenant_id=tenant)
    finally:
        reset_current_tenant(token)


def _admit(tenant: str, job_id: str) -> None:
    token = set_current_tenant(tenant)
    try:
        job = ScanJob(job_id=job_id, tenant_id=tenant, source_id="host", created_at="2026-11-02T00:00:00Z", request=ScanRequest())
        push_ingest.admit_pushed_job(job, {"pushed": True, "scan_id": job_id, "agents": []}, actor="test", request_hash="h")
    finally:
        reset_current_tenant(token)


def _sync_job(tenant: str, job_id: str, *, created_at: str = "2020-01-01T00:00:00Z", result: dict | None = None) -> ScanJob:
    return ScanJob(
        job_id=job_id,
        tenant_id=tenant,
        source_id="host",
        status=JobStatus.RUNNING,
        created_at=created_at,
        request=ScanRequest(),
        result={"pushed": True, "scan_id": job_id} if result is None else result,
    )


def _reap(store: PostgresJobStore, monkeypatch: pytest.MonkeyPatch) -> int:
    from agent_bom.api.scan_job_reconciliation import fail_stale_active_scan_jobs

    monkeypatch.setenv("AGENT_BOM_DISTRIBUTED_SCANS", "1")
    return fail_stale_active_scan_jobs(store, timeout_seconds=1800)


@pytest.fixture
def pushed_route(monkeypatch: pytest.MonkeyPatch):
    """The real HTTP route against real Postgres stores, in distributed mode."""
    from starlette.testclient import TestClient

    from agent_bom.api import audit_log, postgres_common
    from agent_bom.api.idempotency_store import PostgresIdempotencyStore
    from agent_bom.api.postgres_audit import PostgresAuditLog
    from agent_bom.api.postgres_graph import PostgresGraphStore
    from agent_bom.api.server import app, configure_api
    from tests.auth_helpers import PROXY_SECRET

    tenant = _tenant()
    monkeypatch.setenv("AGENT_BOM_DISTRIBUTED_SCANS", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", PROXY_SECRET)
    configure_api(api_key=None)
    token = postgres_common.set_current_tenant(tenant)
    postgres_common.reset_pool()
    monkeypatch.setattr(app, "middleware_stack", None)
    jobs, graph, audit = PostgresJobStore(), PostgresGraphStore(), PostgresAuditLog()
    monkeypatch.setattr(stores, "_store", jobs)
    monkeypatch.setattr(stores, "_graph_store", graph)
    monkeypatch.setattr(stores, "_idempotency_store", PostgresIdempotencyStore())
    monkeypatch.setattr(audit_log, "get_audit_log", lambda: audit)
    headers = {"X-Agent-Bom-Role": "analyst", "X-Agent-Bom-Tenant-ID": tenant, "X-Agent-Bom-Proxy-Secret": PROXY_SECRET}
    try:
        yield TestClient(app, raise_server_exceptions=False), jobs, tenant, headers
    finally:
        postgres_common.reset_pool()
        postgres_common.reset_current_tenant(token)
        configure_api(api_key=None)


def _report(key: str) -> dict:
    return {"source_id": "host", "idempotency_key": key, "agents": [{"name": "a", "agent_type": "custom", "mcp_servers": []}]}


def _expire_reservation(store: PostgresJobStore, tenant: str) -> None:
    with store._scope_connection(all_tenants=True) as conn:
        conn.execute("UPDATE idempotency_keys SET lease_expires_at='2000-01-01T00:00:00Z' WHERE tenant_id=%s", (tenant,))
        conn.commit()


def test_sync_push_killed_mid_ingest_fails_on_lease_expiry_and_the_same_key_recovers(pushed_route, monkeypatch: pytest.MonkeyPatch) -> None:
    client, jobs, tenant, headers = pushed_route

    def killed(*_args, **_kwargs) -> None:  # noqa: ANN002, ANN003
        raise _ProcessKilled

    monkeypatch.setattr("agent_bom.api.routes.observability._persist_graph_snapshot", killed)
    assert client.post("/v1/results/push", headers=headers, json=_report("killed-key")).status_code == 500
    rows = jobs.list_summary(tenant_id=tenant)
    assert [row["status"] for row in rows] == ["running"]
    job_id = rows[0]["job_id"]

    # The owner renews a lease, so nothing is failed while that lease is live.
    assert _queue_status(jobs, tenant, job_id) == "request"
    _reap(jobs, monkeypatch)
    assert _job_in(jobs, tenant, job_id).status is JobStatus.RUNNING

    _expire_lease(jobs, tenant, job_id)
    _reap(jobs, monkeypatch)
    failed = _job_in(jobs, tenant, job_id)
    assert failed.status is JobStatus.FAILED
    assert "Interrupted" in failed.error and failed.completed_at
    assert _queue_row(jobs, tenant, job_id) is None
    receipt = client.get(f"/v1/results/push/{job_id}", headers=headers)
    assert receipt.status_code == 200 and receipt.json()["status"] == "failed"

    monkeypatch.setattr("agent_bom.api.routes.observability._persist_graph_snapshot", lambda *_a, **_k: None)
    _expire_reservation(jobs, tenant)
    retry = client.post("/v1/results/push", headers=headers, json=_report("killed-key"))
    assert retry.status_code == 201, retry.text
    assert retry.json()["job_id"] == job_id
    done = _job_in(jobs, tenant, job_id)
    assert done.status is JobStatus.DONE and done.error is None
    assert _queue_row(jobs, tenant, job_id) is None


def test_completed_sync_push_leaves_no_lease_row(pushed_route) -> None:
    client, jobs, tenant, headers = pushed_route
    response = client.post("/v1/results/push", headers=headers, json=_report("clean-key"))
    assert response.status_code == 201, response.text
    assert _queue_status(jobs, tenant, response.json()["job_id"]) is None


def test_sync_push_failure_compensation_removes_job_and_lease(pushed_route, monkeypatch: pytest.MonkeyPatch) -> None:
    client, jobs, tenant, headers = pushed_route

    def fail(*_args, **_kwargs) -> None:  # noqa: ANN002, ANN003
        raise OSError("graph unavailable")

    monkeypatch.setattr("agent_bom.api.routes.observability._persist_graph_snapshot", fail)
    assert client.post("/v1/results/push", headers=headers, json=_report("rollback-key")).status_code == 503
    assert jobs.list_summary(tenant_id=tenant) == []
    with jobs._scope_connection(all_tenants=True) as conn:
        assert conn.execute("SELECT count(*) FROM scan_dispatch_queue WHERE tenant_id=%s", (tenant,)).fetchone()[0] == 0


def test_old_sync_push_with_a_live_lease_is_never_failed_by_age(pg_store, monkeypatch: pytest.MonkeyPatch) -> None:
    tenant, job_id = _tenant(), uuid4().hex
    token = set_current_tenant(tenant)
    try:
        pg_store.put_with_request_lease(_sync_job(tenant, job_id), "replica-a:1:x", 600)
    finally:
        reset_current_tenant(token)
    _reap(pg_store, monkeypatch)
    assert _job_in(pg_store, tenant, job_id).status is JobStatus.RUNNING
    assert _queue_row(pg_store, tenant, job_id)[0] == "request"
    # A request-owned row is never redelivered: replaying could lose what only the request held.
    assert pg_store.requeue_expired_leases() >= 0
    assert _queue_row(pg_store, tenant, job_id)[0] == "request"


def test_request_lease_heartbeat_renews_until_released(pg_store, monkeypatch: pytest.MonkeyPatch) -> None:
    tenant, job_id = _tenant(), uuid4().hex
    monkeypatch.setattr(push_ingest, "distributed_scans_enabled", lambda: True)
    job = _sync_job(tenant, job_id)
    token = set_current_tenant(tenant)
    try:
        with push_ingest.RequestPushLease(pg_store, job, lease_seconds=3, interval_seconds=0.1) as lease:
            lease.store_job()
            with pg_store._scope_connection(all_tenants=True) as conn:
                conn.execute(
                    "UPDATE scan_dispatch_queue SET lease_expires_at='2000-01-01T00:00:00Z' WHERE tenant_id=%s AND job_id=%s",
                    (tenant, job_id),
                )
                conn.commit()
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                with pg_store._scope_connection(all_tenants=True) as conn:
                    expiry = conn.execute(
                        "SELECT lease_expires_at FROM scan_dispatch_queue WHERE tenant_id=%s AND job_id=%s", (tenant, job_id)
                    ).fetchone()[0]
                if expiry != "2000-01-01T00:00:00Z":
                    break
                time.sleep(0.05)
            assert expiry != "2000-01-01T00:00:00Z"
            job.status = JobStatus.DONE
            job.completed_at = "2026-11-05T00:00:00Z"
            lease.store_job()
            lease.release()
        assert _queue_row(pg_store, tenant, job_id) is None
        pg_store.delete(job_id, tenant_id=tenant)
    finally:
        reset_current_tenant(token)


def test_expired_lease_on_a_finished_job_only_clears_the_row(pg_store, monkeypatch: pytest.MonkeyPatch) -> None:
    tenant, job_id = _tenant(), uuid4().hex
    token = set_current_tenant(tenant)
    try:
        job = _sync_job(tenant, job_id)
        pg_store.put_with_request_lease(job, "replica-a:1:x", 600)
        job.status = JobStatus.DONE
        job.completed_at = "2026-11-05T00:00:00Z"
        pg_store.put(job)
    finally:
        reset_current_tenant(token)
    _expire_lease(pg_store, tenant, job_id)
    _reap(pg_store, monkeypatch)
    assert _job_in(pg_store, tenant, job_id).status is JobStatus.DONE
    assert _queue_row(pg_store, tenant, job_id) is None


def test_poison_push_fails_at_the_attempt_limit_and_can_be_resubmitted(pg_store, monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.api.scan_job_reconciliation import fail_unrecoverable_dispatch_jobs

    graph_calls: list[str] = []

    def _persist(job, report, **_kwargs) -> None:  # noqa: ANN001
        graph_calls.append(job.job_id)
        report["graph_persistence"] = {"status": "persisted", "scan_id": job.job_id}

    monkeypatch.setattr(push_ingest_worker, "_persist_push_graph", _persist)
    monkeypatch.setattr(push_ingest_worker, "_graph_snapshot_exists", lambda _tenant, _scan: False)
    monkeypatch.setattr(push_ingest_worker, "_record_push_trend", lambda *_args, **_kwargs: None)
    tenant, job_id = _tenant(), uuid4().hex
    _admit(tenant, job_id)
    claims = 0
    for _ in range(10):
        claimed = pg_store.claim_next("replica", 600, max_attempts=3)
        while claimed is not None and claimed.job_id != job_id:
            claimed = pg_store.claim_next("replica", 600, max_attempts=3)
        if claimed is None:
            break
        claims += 1
        _expire_lease(pg_store, tenant, job_id)
        # A peer racing the sweep must not redeliver an exhausted row either.
        pg_store.requeue_expired_leases(max_attempts=3)
    assert claims == 3
    assert _queue_row(pg_store, tenant, job_id)[:2] == ("running", 3)
    assert _job_in(pg_store, tenant, job_id).status is JobStatus.PENDING

    assert fail_unrecoverable_dispatch_jobs(pg_store, max_attempts=3) >= 1
    failed = _job_in(pg_store, tenant, job_id)
    assert failed.status is JobStatus.FAILED
    assert "3 attempts" in failed.error
    assert _queue_row(pg_store, tenant, job_id) is None
    assert graph_calls == []

    # Same idempotency key re-admits the same deterministic job with a fresh budget.
    _admit(tenant, job_id)
    assert _queue_row(pg_store, tenant, job_id)[:2] == ("pending", 0)
    claimed = pg_store.claim_next("replica", 600, max_attempts=3)
    while claimed is not None and claimed.job_id != job_id:
        claimed = pg_store.claim_next("replica", 600, max_attempts=3)
    assert claimed is not None and _queue_row(pg_store, tenant, job_id)[1] == 1
    token = set_current_tenant(tenant)
    try:
        pipeline._run_claimed_scan_sync(claimed)
        assert pg_store.get(job_id, tenant_id=tenant).status is JobStatus.DONE
        assert graph_calls == [job_id]
    finally:
        reset_current_tenant(token)


def test_exhausting_one_tenant_leaves_the_same_job_id_in_another_tenant_alone(pg_store) -> None:
    from agent_bom.api.scan_job_reconciliation import fail_unrecoverable_dispatch_jobs

    poisoned, healthy, job_id = _tenant(), _tenant(), uuid4().hex
    for tenant in (poisoned, healthy):
        _admit(tenant, job_id)
    with pg_store._scope_connection(all_tenants=True) as conn:
        conn.execute(
            """UPDATE scan_dispatch_queue SET status='running', attempts=5, claimed_by='w:1:x',
               lease_expires_at='2000-01-01T00:00:00Z' WHERE tenant_id=%s AND job_id=%s""",
            (poisoned, job_id),
        )
        conn.commit()
    fail_unrecoverable_dispatch_jobs(pg_store, max_attempts=5)
    assert _job_in(pg_store, poisoned, job_id).status is JobStatus.FAILED
    assert _queue_row(pg_store, poisoned, job_id) is None
    assert _job_in(pg_store, healthy, job_id).status is JobStatus.PENDING
    assert _queue_row(pg_store, healthy, job_id)[:2] == ("pending", 0)


def test_readmitting_over_a_dead_request_lease_hands_the_row_to_the_queue(pg_store) -> None:
    tenant, job_id = _tenant(), uuid4().hex
    token = set_current_tenant(tenant)
    try:
        pg_store.put_with_request_lease(_sync_job(tenant, job_id), "replica-a:1:x", 600)
    finally:
        reset_current_tenant(token)
    _expire_lease(pg_store, tenant, job_id)
    _admit(tenant, job_id)
    assert _queue_row(pg_store, tenant, job_id) == ("pending", 0, None)
    assert _job_in(pg_store, tenant, job_id).status is JobStatus.PENDING


def test_old_push_with_no_queue_row_fails_but_batch_parents_and_new_pushes_do_not(pg_store, monkeypatch: pytest.MonkeyPatch) -> None:
    tenant = _tenant()
    stranded, compressed, recent, scan, parent = uuid4().hex, uuid4().hex, uuid4().hex, uuid4().hex, uuid4().hex
    fresh = datetime.now(timezone.utc).isoformat()
    token = set_current_tenant(tenant)
    try:
        pg_store.put(_sync_job(tenant, stranded))
        # A real report is stored compressed, so its fields are not plain JSON keys.
        large = {"pushed": True, "scan_id": compressed, "agents": [{"name": uuid4().hex} for _ in range(3000)]}
        pg_store.put(_sync_job(tenant, compressed, result=large))
        pg_store.put(_sync_job(tenant, recent, created_at=fresh))
        pg_store.put(_sync_job(tenant, scan, result={}))
        batch = _sync_job(tenant, parent, result={})
        batch.child_job_ids = [uuid4().hex]
        pg_store.put(batch)
    finally:
        reset_current_tenant(token)
    _reap(pg_store, monkeypatch)
    failed = _job_in(pg_store, tenant, stranded)
    assert failed.status is JobStatus.FAILED and "Interrupted" in failed.error
    assert _job_in(pg_store, tenant, compressed).status is JobStatus.FAILED
    assert _job_in(pg_store, tenant, recent).status is JobStatus.RUNNING
    assert _job_in(pg_store, tenant, scan).status is JobStatus.RUNNING
    assert _job_in(pg_store, tenant, parent).status is JobStatus.RUNNING


def _run_claimed(job: ScanJob, on_complete) -> None:  # noqa: ANN001
    done = threading.Event()

    def _finish(job_id: str, **kwargs) -> None:  # noqa: ANN003
        on_complete(job_id, **kwargs)
        done.set()

    pipeline.submit_claimed_scan_job(job, _finish)
    assert done.wait(30)


def test_transient_store_read_leaves_the_claim_to_expire_and_redeliver(pg_store, monkeypatch: pytest.MonkeyPatch) -> None:
    def _persist(job, report, **_kwargs) -> None:  # noqa: ANN001
        report["graph_persistence"] = {"status": "persisted", "scan_id": job.job_id}

    monkeypatch.setattr(push_ingest_worker, "_persist_push_graph", _persist)
    monkeypatch.setattr(push_ingest_worker, "_graph_snapshot_exists", lambda _tenant, _scan: False)
    monkeypatch.setattr(push_ingest_worker, "_record_push_trend", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(job_read_retry, "READ_RETRY_DELAYS", ())
    tenant, job_id = _tenant(), uuid4().hex
    _admit(tenant, job_id)

    class _Unavailable:
        def get(self, *_args, **_kwargs) -> None:  # noqa: ANN002, ANN003
            raise OSError("pool timeout")

    worker = DistributedScanWorker(pg_store, worker_id="w:1:x", max_concurrent=1)
    claimed = pg_store.claim_next("w:1:x", 600)
    while claimed is not None and claimed.job_id != job_id:
        claimed = pg_store.claim_next("w:1:x", 600)
    assert claimed is not None
    owner = claimed._dispatch_claim_owner
    worker._inflight[(tenant, job_id)] = owner
    monkeypatch.setattr(push_ingest_worker, "_get_store", lambda: _Unavailable())
    _run_claimed(claimed, lambda job_id_, abandoned=False: worker._on_complete(job_id_, owner, tenant, abandoned=abandoned))
    monkeypatch.setattr(push_ingest_worker, "_get_store", lambda: pg_store)

    # Good data is untouched, the worker no longer heartbeats, and the row survives for redelivery.
    assert _job_in(pg_store, tenant, job_id).status is JobStatus.PENDING
    assert _queue_status(pg_store, tenant, job_id) == "running"
    assert not worker._inflight

    _expire_lease(pg_store, tenant, job_id)
    assert pg_store.requeue_expired_leases() >= 1
    redelivered = pg_store.claim_next("w:2:y", 600)
    while redelivered is not None and redelivered.job_id != job_id:
        redelivered = pg_store.claim_next("w:2:y", 600)
    assert redelivered is not None
    token = set_current_tenant(tenant)
    try:
        pipeline._run_claimed_scan_sync(redelivered)
        assert pg_store.get(job_id, tenant_id=tenant).status is JobStatus.DONE
    finally:
        reset_current_tenant(token)


def test_exhausted_child_settles_its_batch_parent(pg_store) -> None:
    from agent_bom.api.scan_job_reconciliation import fail_unrecoverable_dispatch_jobs

    tenant, parent_id, child_id = _tenant(), uuid4().hex, uuid4().hex
    parent = ScanJob(job_id=parent_id, tenant_id=tenant, status=JobStatus.RUNNING, created_at="2026-11-02T00:00:00Z", request=ScanRequest())
    parent.child_job_ids = [child_id]
    parent.batch_id = parent_id
    child = ScanJob(job_id=child_id, tenant_id=tenant, created_at="2026-11-02T00:00:00Z", request=ScanRequest())
    child.parent_job_id = parent_id
    child.batch_id = parent_id
    token = set_current_tenant(tenant)
    try:
        pg_store.put_many_and_enqueue_atomic([parent, child], [child])
    finally:
        reset_current_tenant(token)
    with pg_store._scope_connection(all_tenants=True) as conn:
        conn.execute(
            """UPDATE scan_dispatch_queue SET status='running', attempts=5, claimed_by='w:1:x',
               lease_expires_at='2000-01-01T00:00:00Z' WHERE tenant_id=%s AND job_id=%s""",
            (tenant, child_id),
        )
        conn.commit()
    assert fail_unrecoverable_dispatch_jobs(pg_store, max_attempts=5) >= 1
    assert _job_in(pg_store, tenant, child_id).status is JobStatus.FAILED
    assert _job_in(pg_store, tenant, parent_id).status is JobStatus.FAILED
