"""A restarted API prepares each recent tenant's current graph before the first read asks for it."""

from __future__ import annotations

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
