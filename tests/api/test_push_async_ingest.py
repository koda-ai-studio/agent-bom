"""Asynchronous push ingest, non-blocking idempotency and replica-safe workers."""

from __future__ import annotations

import asyncio
import threading
import time

import httpx
import pytest
from starlette.testclient import TestClient

from agent_bom.api import pipeline, push_ingest_worker, stores
from agent_bom.api.fleet_store import InMemoryFleetStore
from agent_bom.api.idempotency_store import InMemoryIdempotencyStore
from agent_bom.api.models import JobStatus
from agent_bom.api.scan_queue import reset_local_dispatches_for_tests
from agent_bom.api.server import app, set_fleet_store, set_job_store
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import set_idempotency_store

ASYNC = {"Prefer": "respond-async"}


def _payload(key: str = "push-async-1", *, source: str = "laptop-a") -> dict:
    return {
        "source_id": source,
        "idempotency_key": key,
        "agents": [{"name": "proj", "agent_type": "claude-desktop", "mcp_servers": []}],
        "summary": {"total_packages": 0},
    }


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch):
    originals = (stores._get_store(), stores._get_fleet_store(), stores._get_idempotency_store())
    set_job_store(InMemoryJobStore())
    set_fleet_store(InMemoryFleetStore())
    set_idempotency_store(InMemoryIdempotencyStore())
    reset_local_dispatches_for_tests()
    monkeypatch.delenv("AGENT_BOM_PUSH_INGEST_MODE", raising=False)
    yield
    set_job_store(originals[0])
    set_fleet_store(originals[1])
    set_idempotency_store(originals[2])
    reset_local_dispatches_for_tests()


@pytest.fixture
def graph_calls(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    def _persist(job, report, **_kwargs) -> None:  # noqa: ANN001
        calls.append(job.job_id)
        report["graph_persistence"] = {"status": "persisted", "scan_id": job.job_id, "nodes": 3, "edges": 2}

    monkeypatch.setattr(push_ingest_worker, "_persist_push_graph", _persist)
    return calls


def _wait_for(predicate, timeout: float = 10.0) -> None:  # noqa: ANN001
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError("condition not reached")


def test_async_push_returns_202_and_the_worker_commits_once(graph_calls: list[str]) -> None:
    client = TestClient(app, raise_server_exceptions=False)
    accepted = client.post("/v1/results/push", json=_payload(), headers=ASYNC)

    assert accepted.status_code == 202
    body = accepted.json()
    assert body["status"] == "accepted"
    assert body["status_url"] == f"/v1/results/push/{body['job_id']}"
    assert accepted.headers["Retry-After"]
    _wait_for(lambda: client.get(body["status_url"]).json().get("status") == "stored")

    receipt = client.get(body["status_url"]).json()
    assert receipt["graph_persistence"] == {"status": "persisted", "scan_id": body["job_id"], "nodes": 3, "edges": 2}
    stored = stores._get_store().get(body["job_id"], tenant_id="default")
    assert stored is not None and stored.status is JobStatus.DONE
    assert graph_calls == [body["job_id"]]

    replay = client.post("/v1/results/push", json=_payload(), headers=ASYNC)
    assert replay.status_code == 201
    assert replay.json()["job_id"] == body["job_id"]
    assert replay.json()["graph_persistence"]["status"] == "persisted"
    assert graph_calls == [body["job_id"]]
    assert len(stores._get_store().list_all(all_tenants=True)) == 1


def test_retry_while_queued_returns_the_same_job_without_a_duplicate(monkeypatch: pytest.MonkeyPatch, graph_calls: list[str]) -> None:
    monkeypatch.setattr("agent_bom.api.scan_job_dispatch.submit_scan_job", lambda _job: None)
    client = TestClient(app, raise_server_exceptions=False)

    first = client.post("/v1/results/push", json=_payload("queued"), headers=ASYNC)
    second = client.post("/v1/results/push", json=_payload("queued"), headers=ASYNC)

    assert (first.status_code, second.status_code) == (202, 202)
    assert first.json()["job_id"] == second.json()["job_id"]
    assert client.get(first.json()["status_url"]).json()["ingest"] == "pending"
    assert len(stores._get_store().list_all(all_tenants=True)) == 1
    assert graph_calls == []


def test_failed_ingest_is_reported_and_a_retry_with_the_same_key_recovers(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts: list[str] = []

    def _flaky(job, report, **_kwargs) -> None:  # noqa: ANN001
        attempts.append(job.job_id)
        if len(attempts) == 1:
            raise RuntimeError("postgresql://user:secret@db/private")
        report["graph_persistence"] = {"status": "persisted", "scan_id": job.job_id}

    monkeypatch.setattr(push_ingest_worker, "_persist_push_graph", _flaky)
    client = TestClient(app, raise_server_exceptions=False)
    first = client.post("/v1/results/push", json=_payload("flaky"), headers=ASYNC).json()
    _wait_for(lambda: client.get(first["status_url"]).json().get("status") == "failed")
    failed = client.get(first["status_url"])
    assert "secret" not in failed.text

    retry = client.post("/v1/results/push", json=_payload("flaky"), headers=ASYNC)
    assert retry.status_code == 202
    assert retry.json()["job_id"] == first["job_id"]
    _wait_for(lambda: client.get(first["status_url"]).json().get("status") == "stored")
    assert attempts == [first["job_id"], first["job_id"]]
    assert len(stores._get_store().list_all(all_tenants=True)) == 1


def test_push_status_is_tenant_scoped_and_404s_unknown_jobs() -> None:
    client = TestClient(app, raise_server_exceptions=False)
    assert client.get("/v1/results/push/does-not-exist").status_code == 404


def test_a_claimed_push_on_another_replica_runs_the_ingest_not_a_scan(graph_calls: list[str], monkeypatch: pytest.MonkeyPatch) -> None:
    """The distributed claim-loop hands any queued job to ``_run_claimed_scan_sync``."""

    monkeypatch.setattr("agent_bom.api.scan_job_dispatch.submit_scan_job", lambda _job: None)
    client = TestClient(app, raise_server_exceptions=False)
    job_id = client.post("/v1/results/push", json=_payload("replica"), headers=ASYNC).json()["job_id"]
    claimed = stores._get_store().get(job_id, tenant_id="default")
    assert claimed is not None and claimed.status is JobStatus.PENDING

    pipeline._run_claimed_scan_sync(claimed)
    pipeline._run_claimed_scan_sync(claimed)  # a redelivered claim is a no-op

    assert graph_calls == [job_id]
    done = stores._get_store().get(job_id, tenant_id="default")
    assert done is not None and done.status is JobStatus.DONE


def test_server_mode_can_force_async_and_endpoint_inventory_stays_synchronous(
    monkeypatch: pytest.MonkeyPatch, graph_calls: list[str]
) -> None:
    monkeypatch.setenv("AGENT_BOM_PUSH_INGEST_MODE", "async")
    monkeypatch.setattr("agent_bom.api.routes.observability._persist_graph_snapshot", lambda _job, _report, **_kwargs: None)
    client = TestClient(app, raise_server_exceptions=False)
    assert client.post("/v1/results/push", json=_payload("forced")).status_code == 202
    inventory = {
        "source_id": "endpoint-a",
        "idempotency_key": "inventory",
        "endpoint_inventory": {
            "schema_version": "1",
            "platform": {"system": "Linux", "release": "6", "machine": "x86_64"},
            "privacy": {},
            "collectors": [{"name": "processes", "status": "complete", "item_count": 1, "message": ""}],
        },
    }
    assert client.post("/v1/results/push", json=inventory).status_code == 201


@pytest.mark.asyncio
async def test_a_slow_commit_never_blocks_the_event_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    """While one push spends seconds committing, other endpoints and a same-key retry answer at once."""

    started = threading.Event()

    def _slow_graph(_job, _report, **_kwargs) -> None:  # noqa: ANN001
        started.set()
        time.sleep(2.0)

    monkeypatch.setattr("agent_bom.api.routes.observability._persist_graph_snapshot", _slow_graph)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        slow = asyncio.create_task(client.post("/v1/results/push", json=_payload("slow-sync")))
        assert await asyncio.to_thread(started.wait, 10)

        began = time.monotonic()
        health = await client.get("/health")
        health_elapsed = time.monotonic() - began

        began = time.monotonic()
        retry = await client.post("/v1/results/push", json=_payload("slow-sync"))
        retry_elapsed = time.monotonic() - began

        committed = await slow

    assert health.status_code == 200
    assert health_elapsed < 0.2, health_elapsed
    assert retry.status_code == 202, retry.text
    assert retry_elapsed < 0.5, retry_elapsed
    assert retry.headers["Retry-After"]
    assert retry.json()["job_id"] == committed.json()["job_id"]
    assert committed.status_code == 201
