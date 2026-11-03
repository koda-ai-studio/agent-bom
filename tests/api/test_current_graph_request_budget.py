"""A caller-facing cold read cannot own an unbounded projection build."""

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from starlette.exceptions import HTTPException

from agent_bom.api.current_graph import CurrentGraphStore
from agent_bom.api.finding_read_context import finding_read_scope
from agent_bom.core.estate_read_boundary import estate_read_boundary
from tests.api.test_current_graph_estate import estate, record  # noqa: F401
from tests.api.test_current_graph_unpinned_reads import TENANT, _hold_materialize
from tests.auth_helpers import proxy_headers
from tests.test_api_read_contracts import empty_estate_client  # noqa: F401


@pytest.mark.parametrize("previous", [False, True])
def test_request_releases_slow_build_and_reports_state(estate, monkeypatch, previous):  # noqa: F811
    monkeypatch.setenv("AGENT_BOM_CURRENT_GRAPH_BUILD_WAIT_MS", "2000" if previous else "20")
    record(estate, 8, "repo-a", "old-package")
    store = CurrentGraphStore(estate[1], estate[0])
    old = store.latest_snapshot_id(tenant_id=TENANT) if previous else ""
    record(estate, 9, "repo-a", "new-package")
    entered, release = _hold_materialize(store)
    done = threading.Event()

    def request():
        try:
            with estate_read_boundary(), finding_read_scope():
                identity = store.latest_snapshot_id(tenant_id=TENANT)
                return identity, store.snapshot_stats(tenant_id=TENANT)
        except HTTPException as exc:
            return exc
        finally:
            done.set()

    with ThreadPoolExecutor(max_workers=1) as workers:
        reader = workers.submit(request)
        assert entered.wait(5)
        try:
            returned_before_build = done.wait(0.5)
        finally:
            release.set()
        result = reader.result(timeout=10)
    assert returned_before_build, "caller waited for the entire cold build"
    if previous:
        assert result[0] == old
        assert result[1]["collection_coverage"]["refresh_status"] == "building"
        assert result[1]["collection_coverage"]["freshness"] == "previous_generation"
    else:
        assert isinstance(result, HTTPException)
        assert result.status_code == 503
        assert result.detail["code"] == "current_estate_building"
        assert result.headers["Retry-After"] == "1"
    # Internal/commit warmers still wait for a complete generation. The queued
    # work and a concurrent warmer must coalesce through the existing build gate.
    final = store.latest_snapshot_id(tenant_id=TENANT)
    assert final != old
    assert set(store.load_graph(tenant_id=TENANT).nodes) == {"new-package"}


def test_background_queue_coalesces_and_bounds_tenant_work():
    from agent_bom.api.current_graph_builds import CurrentBuildQueue
    from agent_bom.api.postgres_common import _current_tenant

    release, entered = threading.Event(), threading.Event()
    seen = []

    class Store:
        def _current_id(self, tenant):
            seen.append((tenant, _current_tenant.get()))
            entered.set()
            assert release.wait(5)
            return tenant

    queue, store = CurrentBuildQueue(workers=1, capacity=2), Store()
    try:
        alpha = queue.submit(store, "alpha")
        assert entered.wait(5)
        assert queue.submit(store, "alpha") is alpha
        beta = queue.submit(store, "beta")
        assert beta is not alpha
        assert queue.submit(store, "overflow") is None
        release.set()
        assert alpha.result(timeout=5) == "alpha"
        assert beta.result(timeout=5) == "beta"
        assert seen == [("alpha", "alpha"), ("beta", "beta")]
    finally:
        release.set()
        queue.executor.shutdown(wait=True)


def test_failed_background_work_is_retryable_and_does_not_expose_source(monkeypatch, caplog):
    from agent_bom.api import current_graph_builds

    class Store:
        calls = 0

        def _current_id(self, tenant):
            self.calls += 1
            if self.calls == 1:
                raise ValueError("private-test-source-location")
            return "complete-generation"

    queue, store = current_graph_builds.CurrentBuildQueue(), Store()
    monkeypatch.setattr(current_graph_builds, "_QUEUE", queue)
    try:
        with pytest.raises(HTTPException) as error:
            current_graph_builds.await_current_build(store, "alpha", seconds=1)
        assert error.value.detail["code"] == "current_estate_build_unavailable"
        assert "private-test-source-location" not in str(error.value.detail) + caplog.text
        assert current_graph_builds.await_current_build(store, "alpha", seconds=1) == "complete-generation"
    finally:
        queue.executor.shutdown(wait=True)


@pytest.mark.parametrize("path", ["/v1/graph?limit=100&view=canvas", "/v1/graph/rollup?limit=100"])
def test_http_previous_view_marks_refresh_without_caching_freshness(estate, empty_estate_client, monkeypatch, path):  # noqa: F811
    from agent_bom.api import stores

    monkeypatch.setattr(stores, "_store", estate[0])
    monkeypatch.setattr(stores, "_graph_store", estate[1])
    monkeypatch.setenv("AGENT_BOM_CURRENT_GRAPH_BUILD_WAIT_MS", "20")
    record(estate, 8, "repo-a", "old-package")
    store = stores._get_graph_store()
    old = store.latest_snapshot_id(tenant_id=TENANT)
    client = empty_estate_client
    headers = proxy_headers(role="analyst", tenant=TENANT)
    warm = client.get(path, headers=headers)
    assert warm.status_code == 200, warm.text
    record(estate, 9, "repo-a", "new-package")
    entered, release = _hold_materialize(store)
    try:
        response = client.get(path, headers=headers)
        assert entered.is_set()
        assert response.status_code == 200, response.text
        assert response.json()["scan_id"] == old
        assert response.json()["collection_coverage"]["freshness"] == "previous_generation"
    finally:
        release.set()
    store.latest_snapshot_id(tenant_id=TENANT)
    fresh = client.get(path, headers=headers)
    assert fresh.status_code == 200, fresh.text
    assert fresh.json()["scan_id"] != old
    assert "freshness" not in fresh.json()["collection_coverage"]
