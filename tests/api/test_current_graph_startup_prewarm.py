"""A restarted API prepares each recent tenant's current graph before the first read asks for it."""

from __future__ import annotations

import threading
import time

import pytest
from starlette.exceptions import HTTPException

from agent_bom.api import current_graph_prewarm
from agent_bom.api.current_graph import CurrentGraphStore
from agent_bom.api.finding_read_context import finding_read_scope
from agent_bom.core.estate_read_boundary import estate_read_boundary
from tests.api.test_current_graph_estate import estate, record  # noqa: F401
from tests.api.test_current_graph_unpinned_reads import TENANT, private_build_queue  # noqa: F401


def _request_read(store: CurrentGraphStore, tenant: str = TENANT):
    """An HTTP read: inside the estate boundary, so it waits only the request budget."""
    try:
        with estate_read_boundary(), finding_read_scope():
            return store.latest_snapshot_id(tenant_id=tenant), set(store.load_graph(tenant_id=tenant).nodes)
    except HTTPException as exc:
        return exc


@pytest.fixture
def no_request_wait(monkeypatch):
    # A read that cannot wait at all shows whether anything prepared the graph before it.
    monkeypatch.setenv("AGENT_BOM_CURRENT_GRAPH_BUILD_WAIT_MS", "0")


def test_first_read_after_restart_is_refused_without_a_prewarm(estate, no_request_wait):  # noqa: F811
    record(estate, 8, "repo-a", "package-a")
    restarted = CurrentGraphStore(estate[1], estate[0])
    refused = _request_read(restarted)
    assert isinstance(refused, HTTPException) and refused.status_code == 503
    assert refused.detail["code"] == "current_estate_building"
    assert refused.headers["Retry-After"] == "1"


def test_startup_prewarm_serves_the_first_read_after_restart(estate, no_request_wait):  # noqa: F811
    record(estate, 8, "repo-a", "package-a")
    record(estate, 9, "repo-b", "package-b")
    restarted = CurrentGraphStore(estate[1], estate[0])

    summary = current_graph_prewarm.prewarm_current_graphs(restarted, estate[0], per_tenant_seconds=30)

    assert summary["status"] == "complete", summary
    assert summary["tenants_prepared"] == 1 and summary["tenants_skipped"] == 0
    served = _request_read(restarted)
    assert not isinstance(served, HTTPException), served.detail
    identity, nodes = served
    assert identity.startswith("current-estate:")
    assert nodes == {"package-a", "package-b"}


def test_prewarm_is_tenant_scoped_newest_first_and_reports_what_it_skipped(estate, no_request_wait, monkeypatch):  # noqa: F811
    record(estate, 7, "repo-a", "old-tenant-package", tenant="older-tenant")
    record(estate, 9, "repo-a", "new-tenant-package", tenant=TENANT)
    monkeypatch.setattr(current_graph_prewarm, "MAX_TENANTS", 1)
    restarted = CurrentGraphStore(estate[1], estate[0])

    summary = current_graph_prewarm.prewarm_current_graphs(restarted, estate[0], per_tenant_seconds=30)

    assert summary["status"] == "incomplete" and summary["reason"] == "tenant_cap", summary
    assert summary["tenants_prepared"] == 1 and summary["tenants_skipped"] == 1
    _identity, nodes = _request_read(restarted, TENANT)
    assert nodes == {"new-tenant-package"}
    assert isinstance(_request_read(restarted, "older-tenant"), HTTPException)


def test_prewarm_with_no_completed_scans_touches_no_graph_store(estate):  # noqa: F811
    touched: list[str] = []

    class Untouchable:
        def __getattr__(self, name):
            touched.append(name)
            raise AttributeError(name)

    summary = current_graph_prewarm.prewarm_current_graphs(Untouchable(), estate[0], per_tenant_seconds=1)
    assert summary == {"status": "complete", "tenants_prepared": 0, "tenants_skipped": 0, "tenants_failed": 0}
    assert touched == []


def test_a_failing_tenant_is_counted_and_never_raises(estate, monkeypatch):  # noqa: F811
    record(estate, 8, "repo-a", "package-a")
    restarted = CurrentGraphStore(estate[1], estate[0])

    def broken(*_args, **_kwargs):
        raise RuntimeError("database unavailable: postgresql://user:secret@db/agent_bom")

    monkeypatch.setattr(restarted, "_materialize", broken)
    summary = current_graph_prewarm.prewarm_current_graphs(restarted, estate[0], per_tenant_seconds=5)
    assert summary["status"] == "incomplete" and summary["tenants_failed"] == 1, summary
    assert "secret" not in repr(summary)


def test_startup_prewarm_runs_off_the_event_loop_and_can_be_disabled(estate, monkeypatch):  # noqa: F811
    record(estate, 8, "repo-a", "package-a")
    monkeypatch.setenv("AGENT_BOM_CURRENT_GRAPH_PREWARM", "0")
    assert current_graph_prewarm.start_current_graph_prewarm() is None
    monkeypatch.setenv("AGENT_BOM_CURRENT_GRAPH_PREWARM", "1")
    thread = current_graph_prewarm.start_current_graph_prewarm()
    assert thread is not None and thread.daemon
    thread.join(30)
    assert not thread.is_alive()
    assert current_graph_prewarm.last_run()["tenants_prepared"] == 1


def test_api_lifespan_starts_the_prewarm(monkeypatch):
    from fastapi.testclient import TestClient

    from agent_bom.api import server
    from agent_bom.api.store import InMemoryJobStore

    started = []
    monkeypatch.setattr(current_graph_prewarm, "start_current_graph_prewarm", lambda: started.append(True))
    monkeypatch.setattr(server, "_get_store", lambda: InMemoryJobStore())
    with TestClient(server.app):
        pass
    assert started == [True]


@pytest.fixture
def gated_prewarm(monkeypatch, tmp_path):
    """A running API whose start-up prewarm blocks until the test releases it."""
    from agent_bom.api import server
    from agent_bom.api import stores as api_stores

    monkeypatch.setenv("AGENT_BOM_DB", str(tmp_path / "control-plane.db"))
    monkeypatch.setenv("AGENT_BOM_GRAPH_DB", str(tmp_path / "graph.db"))
    monkeypatch.setenv("AGENT_BOM_CURRENT_GRAPH_PREWARM", "1")
    monkeypatch.delenv("AGENT_BOM_DEMO_ESTATE", raising=False)
    started, release = threading.Event(), threading.Event()

    def blocking_prewarm(*_args, **_kwargs):
        started.set()
        release.wait(30)
        return {"status": "complete", "tenants_prepared": 1, "tenants_skipped": 0, "tenants_failed": 0}

    monkeypatch.setattr(current_graph_prewarm, "prewarm_current_graphs", blocking_prewarm)
    server._shutting_down = False
    original = (api_stores._store, api_stores._graph_store, api_stores._trend_store)
    api_stores._store = api_stores._graph_store = api_stores._trend_store = None
    try:
        yield server, started, release
    finally:
        release.set()
        api_stores._store, api_stores._graph_store, api_stores._trend_store = original


def _wait_for_prewarm_end(seconds: float = 10) -> None:
    deadline = time.monotonic() + seconds
    while current_graph_prewarm.last_run()["status"] == "running" and time.monotonic() < deadline:
        time.sleep(0.02)


def test_readiness_waits_for_the_startup_prewarm_while_liveness_answers(gated_prewarm):
    from fastapi.testclient import TestClient

    server, started, release = gated_prewarm
    with TestClient(server.app) as client:
        assert started.wait(10)
        warming = client.get("/readyz")
        assert warming.status_code == 503
        assert warming.json() == {"status": "not_ready", "reason": "current_graph_prewarming"}
        for path in ("/health", "/healthz", "/livez"):
            assert client.get(path).status_code == 200, path

        release.set()
        _wait_for_prewarm_end()
        ready = client.get("/readyz")
        assert ready.status_code == 200, ready.json()
        assert ready.json() == {"status": "ready"}


def test_readiness_stops_waiting_for_a_prewarm_past_its_bound(gated_prewarm, monkeypatch):
    from fastapi.testclient import TestClient

    server, started, _release = gated_prewarm
    monkeypatch.setenv("AGENT_BOM_CURRENT_GRAPH_PREWARM_READY_SECONDS", "0")
    with TestClient(server.app) as client:
        assert started.wait(10)
        assert current_graph_prewarm.last_run()["status"] == "running"
        # Past the bound the replica takes traffic; reads build on demand with Retry-After.
        assert client.get("/readyz").status_code == 200


def test_readiness_is_not_held_when_the_prewarm_is_disabled(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_CURRENT_GRAPH_PREWARM", "0")
    assert current_graph_prewarm.start_current_graph_prewarm() is None
    assert current_graph_prewarm.startup_prewarm_holding_readiness() is False


def test_readiness_is_held_from_the_moment_the_prewarm_is_started(monkeypatch):
    """No window between lifespan start-up and the thread's first line reports ready."""
    gate = threading.Event()
    monkeypatch.setenv("AGENT_BOM_CURRENT_GRAPH_PREWARM", "1")
    monkeypatch.setattr(current_graph_prewarm, "_run", lambda: gate.wait(10))
    thread = current_graph_prewarm.start_current_graph_prewarm()
    try:
        assert current_graph_prewarm.startup_prewarm_holding_readiness() is True
    finally:
        gate.set()
        assert thread is not None
        thread.join(10)


def test_a_failed_prewarm_releases_readiness_instead_of_staying_running(monkeypatch):
    from agent_bom.api import current_graph_prewarm

    def _boom(*_args, **_kwargs):
        raise RuntimeError("graph store unavailable: postgresql://user:secret@db/x")

    current_graph_prewarm.reset_current_graph_prewarm()
    monkeypatch.setattr(current_graph_prewarm, "prewarm_current_graphs", _boom)
    current_graph_prewarm._LAST_RUN.update(status="running")
    current_graph_prewarm._run()
    status = dict(current_graph_prewarm._LAST_RUN)
    assert status["status"] == "incomplete"
    assert status["reason"] == "prewarm_failed"
    assert "secret" not in str(status)


def test_a_job_store_that_cannot_open_releases_readiness_without_a_raw_traceback(monkeypatch, caplog):
    from agent_bom.api import stores

    def _no_store():
        raise RuntimeError("store init failed: password=hunter2 postgresql://user:hunter2@db/x")

    hooked: list[object] = []
    monkeypatch.setattr(threading, "excepthook", hooked.append)
    monkeypatch.setattr(stores, "_get_store", _no_store)
    monkeypatch.setenv("AGENT_BOM_CURRENT_GRAPH_PREWARM", "1")
    current_graph_prewarm.reset_current_graph_prewarm()
    with caplog.at_level("WARNING", logger="agent_bom.api.current_graph_prewarm"):
        thread = current_graph_prewarm.start_current_graph_prewarm()
        assert thread is not None
        thread.join(10)

    assert not thread.is_alive()
    assert hooked == []
    assert current_graph_prewarm.last_run() == {"status": "incomplete", "reason": "prewarm_failed"}
    assert current_graph_prewarm.startup_prewarm_holding_readiness() is False
    assert "Current graph prewarm failed" in caplog.text
    assert "hunter2" not in caplog.text
