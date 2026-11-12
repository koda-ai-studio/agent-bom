"""A dispatch that arrives while the same job's previous worker is still finishing is never lost."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterator

import pytest
from starlette.testclient import TestClient

from agent_bom.api import push_ingest_worker, scan_queue, stores
from agent_bom.api.fleet_store import InMemoryFleetStore
from agent_bom.api.idempotency_store import InMemoryIdempotencyStore
from agent_bom.api.models import ScanJob, ScanRequest
from agent_bom.api.scan_queue import reset_local_dispatches_for_tests
from agent_bom.api.server import app, set_fleet_store, set_job_store
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import set_idempotency_store

ASYNC = {"Prefer": "respond-async"}
HOLD_SECONDS = 30


def _payload(key: str) -> dict:
    return {
        "source_id": "laptop-a",
        "idempotency_key": key,
        "agents": [{"name": "proj", "agent_type": "claude-desktop", "mcp_servers": []}],
        "summary": {"total_packages": 0},
    }


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    originals = (stores._get_store(), stores._get_fleet_store(), stores._get_idempotency_store())
    set_job_store(InMemoryJobStore())
    set_fleet_store(InMemoryFleetStore())
    set_idempotency_store(InMemoryIdempotencyStore())
    reset_local_dispatches_for_tests()
    monkeypatch.delenv("AGENT_BOM_PUSH_INGEST_MODE", raising=False)
    monkeypatch.setattr(push_ingest_worker, "_COMMIT_LISTENERS", [])
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
        report["graph_persistence"] = {"status": "persisted", "scan_id": job.job_id, "nodes": 1, "edges": 0}

    monkeypatch.setattr(push_ingest_worker, "_persist_push_graph", _persist)
    return calls


class _Gate:
    """Holds the first pass through a step until the test releases it."""

    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()
        self._first = True

    def hold_once(self) -> None:
        if not self._first:
            return
        self._first = False
        self.entered.set()
        assert self.release.wait(HOLD_SECONDS), "test never released the held worker"


def _wait_for(predicate: Callable[[], bool], timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError("condition not reached")


def _no_local_dispatch_held() -> bool:
    with scan_queue._local_dispatch_lock:
        return not scan_queue._local_dispatches


def _status(client: TestClient, url: str) -> str:
    return str(client.get(url).json().get("status"))


def test_a_push_re_admitted_while_the_previous_worker_finishes_is_stored(graph_calls: list[str]) -> None:
    """Retention removed the job while its worker was still in its post-commit step; the same push is admitted again."""

    gate = _Gate()
    push_ingest_worker.register_push_commit_listener(lambda _tenant: gate.hold_once())
    client = TestClient(app, raise_server_exceptions=False)
    first = client.post("/v1/results/push", json=_payload("retained"), headers=ASYNC).json()
    assert gate.entered.wait(HOLD_SECONDS)
    assert _status(client, first["status_url"]) == "stored"

    assert stores._get_store().delete(first["job_id"], tenant_id="default")
    again = client.post("/v1/results/push", json=_payload("retained"), headers=ASYNC)
    assert again.status_code == 202, again.text
    assert again.json()["job_id"] == first["job_id"]
    gate.release.set()

    _wait_for(lambda: _status(client, first["status_url"]) == "stored")
    _wait_for(_no_local_dispatch_held)
    assert graph_calls == [first["job_id"], first["job_id"]]


def test_a_retry_of_a_failed_push_while_its_worker_finishes_is_stored(monkeypatch: pytest.MonkeyPatch) -> None:
    """The worker published ``failed`` and is still unwinding when the client's retry re-admits the job."""

    attempts: list[str] = []
    gate = _Gate()

    def _flaky(job, report, **_kwargs) -> None:  # noqa: ANN001
        attempts.append(job.job_id)
        if len(attempts) == 1:
            raise RuntimeError("graph store unavailable")
        report["graph_persistence"] = {"status": "persisted", "scan_id": job.job_id}

    record_failure = push_ingest_worker._record_ingest_failure

    def _record_then_hold(*args, **kwargs) -> None:  # noqa: ANN002, ANN003
        record_failure(*args, **kwargs)
        gate.hold_once()

    monkeypatch.setattr(push_ingest_worker, "_persist_push_graph", _flaky)
    monkeypatch.setattr(push_ingest_worker, "_record_ingest_failure", _record_then_hold)
    client = TestClient(app, raise_server_exceptions=False)
    first = client.post("/v1/results/push", json=_payload("flaky"), headers=ASYNC).json()
    assert gate.entered.wait(HOLD_SECONDS)
    assert _status(client, first["status_url"]) == "failed"

    retry = client.post("/v1/results/push", json=_payload("flaky"), headers=ASYNC)
    assert retry.status_code == 202, retry.text
    gate.release.set()

    _wait_for(lambda: _status(client, first["status_url"]) == "stored")
    _wait_for(_no_local_dispatch_held)
    assert attempts == [first["job_id"], first["job_id"]]


def test_a_replay_of_an_in_flight_admission_is_not_processed_twice(monkeypatch: pytest.MonkeyPatch) -> None:
    """A replay re-offers the pending job while its worker runs; the finished admission must not run again."""

    calls: list[str] = []
    gate = _Gate()

    def _held(job, report, **_kwargs) -> None:  # noqa: ANN001
        calls.append(job.job_id)
        gate.hold_once()
        report["graph_persistence"] = {"status": "persisted", "scan_id": job.job_id}

    monkeypatch.setattr(push_ingest_worker, "_persist_push_graph", _held)
    client = TestClient(app, raise_server_exceptions=False)
    first = client.post("/v1/results/push", json=_payload("replayed"), headers=ASYNC).json()
    assert gate.entered.wait(HOLD_SECONDS)

    replay = client.post("/v1/results/push", json=_payload("replayed"), headers=ASYNC)
    assert replay.status_code == 202, replay.text
    gate.release.set()

    _wait_for(lambda: _status(client, first["status_url"]) == "stored")
    _wait_for(_no_local_dispatch_held)
    assert calls == [first["job_id"]]


def _scan_job(job_id: str, tenant_id: str) -> ScanJob:
    return ScanJob(job_id=job_id, tenant_id=tenant_id, created_at="2026-11-11T00:00:00Z", request=ScanRequest())


def test_local_dispatch_claims_are_scoped_per_tenant_and_carry_a_rerun_request() -> None:
    from agent_bom.api.scan_queue import claim_local_dispatch, finish_local_dispatch

    a = _scan_job("same-id", "tenant-a")
    b = _scan_job("same-id", "tenant-b")

    assert claim_local_dispatch(a)
    assert claim_local_dispatch(b), "another tenant's job with the same id is not the same dispatch"
    assert not claim_local_dispatch(a)

    assert finish_local_dispatch(a) is a, "a dispatch refused while in flight is handed back to the finishing worker"
    assert not claim_local_dispatch(_scan_job("same-id", "tenant-a")), "the claim stays with the rerun"
    assert finish_local_dispatch(a) is not None, "a request made during the rerun is kept too"
    assert finish_local_dispatch(a) is None
    assert claim_local_dispatch(a), "the claim is released once no rerun is requested"
    assert finish_local_dispatch(a) is None
    assert finish_local_dispatch(b) is None
    assert _no_local_dispatch_held()
