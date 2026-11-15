"""While a new current-estate generation builds, reads serve the last promoted one at once, labelled.

Only a cold start (no promoted generation for the tenant) keeps the bounded
read-your-writes wait. A served previous generation is never presented as
current, never mixes with the new one, and never crosses tenants.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from starlette.exceptions import HTTPException

from agent_bom.api import current_graph_builds
from agent_bom.api.current_graph import CurrentGraphStore
from agent_bom.api.current_graph_builds import await_current_build
from agent_bom.api.finding_read_context import finding_read_scope
from agent_bom.core.estate_read_boundary import estate_read_boundary
from tests.api.test_current_graph_estate import estate, record  # noqa: F401
from tests.api.test_current_graph_unpinned_reads import TENANT, _hold_materialize, private_build_queue  # noqa: F401
from tests.auth_helpers import proxy_headers
from tests.test_api_read_contracts import empty_estate_client  # noqa: F401


def _request(store: CurrentGraphStore, tenant: str = TENANT):
    """One caller-facing read: the generation it resolved, its stats and its node set."""
    try:
        with estate_read_boundary(), finding_read_scope():
            identity = store.latest_snapshot_id(tenant_id=tenant)
            return identity, store.snapshot_stats(tenant_id=tenant), set(store.load_graph(tenant_id=tenant).nodes)
    except HTTPException as exc:
        return exc


def _served_while_held(store: CurrentGraphStore, tenant: str = TENANT):
    entered, release = _hold_materialize(store)
    done = threading.Event()

    def read():
        try:
            return _request(store, tenant)
        finally:
            done.set()

    with ThreadPoolExecutor(max_workers=1) as workers:
        reader = workers.submit(read)
        try:
            returned = done.wait(1.0)
        finally:
            release.set()
        result = reader.result(timeout=10)
    assert entered.is_set(), "the read never started the rebuild"
    return returned, result


def test_rebuild_serves_previous_generation_without_waiting_and_labels_it(estate, monkeypatch):  # noqa: F811
    # A generous budget: today's refresh path still spends part of it before falling back.
    monkeypatch.setenv("AGENT_BOM_CURRENT_GRAPH_BUILD_WAIT_MS", "5000")
    waits: list[float] = []
    original = current_graph_builds.await_current_build

    def spy(store, tenant, *, seconds, prepared=None):
        waits.append(seconds)
        return original(store, tenant, seconds=seconds, prepared=prepared)

    record(estate, 8, "repo-a", "old-package")
    store = CurrentGraphStore(estate[1], estate[0])
    old = store.latest_snapshot_id(tenant_id=TENANT)
    old_created = store._projection_store.snapshots_by_ids(tenant_id=TENANT, scan_ids={old})[0]["created_at"]
    record(estate, 9, "repo-a", "new-package")
    monkeypatch.setattr(current_graph_builds, "await_current_build", spy)

    returned, result = _served_while_held(store)

    assert returned, "a refresh read waited on the rebuild"
    assert waits and all(seconds == 0 for seconds in waits), waits
    identity, stats, nodes = result
    assert identity == old
    assert nodes == {"old-package"}, "one response mixed generations"
    coverage = stats["collection_coverage"]
    assert coverage["freshness"] == "previous_generation"
    assert coverage["refresh_status"] == "building"
    assert coverage["as_of"] == old_created
    assert stats["snapshot_generation"] == old.removeprefix("current-estate:")

    new = original(store, TENANT, seconds=10)
    assert new and new != old
    identity, stats, nodes = _request(store)
    assert identity == new
    assert nodes == {"new-package"}
    assert "freshness" not in stats["collection_coverage"]
    assert "as_of" not in stats["collection_coverage"]


def test_cold_start_keeps_the_bounded_wait_and_refuses(estate, monkeypatch):  # noqa: F811
    monkeypatch.setenv("AGENT_BOM_CURRENT_GRAPH_BUILD_WAIT_MS", "20")
    record(estate, 9, "repo-a", "only-package")
    store = CurrentGraphStore(estate[1], estate[0])

    _returned, result = _served_while_held(store)

    assert isinstance(result, HTTPException)
    assert result.status_code == 503
    assert result.detail["code"] == "current_estate_building"


def test_restarted_worker_serves_the_promoted_generation_from_the_shared_projection(estate, monkeypatch):  # noqa: F811
    """A sibling or restarted worker has no in-process cache, but the promoted generation is on disk."""
    monkeypatch.setenv("AGENT_BOM_CURRENT_GRAPH_BUILD_WAIT_MS", "20")
    record(estate, 8, "repo-a", "old-package")
    first = CurrentGraphStore(estate[1], estate[0])
    old = first.latest_snapshot_id(tenant_id=TENANT)
    assert first._cache_path == CurrentGraphStore(estate[1], estate[0])._cache_path, "projection cache is not shared"
    record(estate, 9, "repo-a", "new-package")
    restarted = CurrentGraphStore(estate[1], estate[0])

    returned, result = _served_while_held(restarted)

    assert returned
    assert not isinstance(result, HTTPException), result
    identity, stats, nodes = result
    assert identity == old
    assert nodes == {"old-package"}
    assert stats["collection_coverage"]["freshness"] == "previous_generation"
    assert stats["collection_coverage"]["as_of"]
    final = await_current_build(restarted, TENANT, seconds=10)
    assert final and final != old


def test_promotion_stamp_from_another_projection_format_is_not_served(estate, monkeypatch):  # noqa: F811
    monkeypatch.setenv("AGENT_BOM_CURRENT_GRAPH_BUILD_WAIT_MS", "20")
    record(estate, 8, "repo-a", "old-package")
    first = CurrentGraphStore(estate[1], estate[0])
    first.latest_snapshot_id(tenant_id=TENANT)
    from agent_bom.api import current_graph

    monkeypatch.setattr(current_graph, "_PROJECTION_FORMAT", current_graph._PROJECTION_FORMAT + 1)
    record(estate, 9, "repo-a", "new-package")
    upgraded = CurrentGraphStore(estate[1], estate[0])

    _returned, result = _served_while_held(upgraded)

    assert isinstance(result, HTTPException)
    assert result.detail["code"] == "current_estate_building"


def test_previous_generation_never_crosses_tenants(estate, monkeypatch):  # noqa: F811
    monkeypatch.setenv("AGENT_BOM_CURRENT_GRAPH_BUILD_WAIT_MS", "20")
    record(estate, 8, "repo-a", "alpha-package")
    store = CurrentGraphStore(estate[1], estate[0])
    alpha = store.latest_snapshot_id(tenant_id=TENANT)
    record(estate, 9, "repo-b", "beta-package", tenant="beta-tenant")
    restarted = CurrentGraphStore(estate[1], estate[0])

    _returned, result = _served_while_held(restarted, tenant="beta-tenant")

    assert isinstance(result, HTTPException), "beta was served a generation it never had"
    assert result.detail["code"] == "current_estate_building"
    with estate_read_boundary(), finding_read_scope():
        assert restarted.latest_snapshot_id(tenant_id=TENANT) == alpha
        assert set(restarted.load_graph(tenant_id=TENANT).nodes) == {"alpha-package"}


def test_worker_reads_outside_a_request_still_build_synchronously(estate):  # noqa: F811
    """Background and CLI reads (no request boundary) keep their exact, synchronous view."""
    record(estate, 8, "repo-a", "old-package")
    store = CurrentGraphStore(estate[1], estate[0])
    old = store.latest_snapshot_id(tenant_id=TENANT)
    record(estate, 9, "repo-a", "new-package")
    assert store.latest_snapshot_id(tenant_id=TENANT) != old
    assert set(store.load_graph(tenant_id=TENANT).nodes) == {"new-package"}


@pytest.mark.parametrize(
    "path",
    [
        "/v1/graph?limit=100",
        "/v1/graph?limit=100&view=summary",
        "/v1/graph/search?q=package",
        "/v1/graph/incident-edges?node_id=old-package",
    ],
)
def test_http_reads_label_the_previous_generation_with_its_time(estate, empty_estate_client, monkeypatch, path):  # noqa: F811
    from agent_bom.api import stores

    monkeypatch.setattr(stores, "_store", estate[0])
    monkeypatch.setattr(stores, "_graph_store", estate[1])
    monkeypatch.setenv("AGENT_BOM_CURRENT_GRAPH_BUILD_WAIT_MS", "5000")
    record(estate, 8, "repo-a", "old-package")
    store = stores._get_graph_store()
    headers = proxy_headers(role="analyst", tenant=TENANT)
    assert empty_estate_client.get(path, headers=headers).status_code == 200
    old = await_current_build(store, TENANT, seconds=10)
    assert old
    entered, release = _hold_materialize(store)
    record(estate, 9, "repo-a", "new-package")
    try:
        response = empty_estate_client.get(path, headers=headers)
        assert entered.wait(5)
    finally:
        release.set()
    assert response.status_code == 200, response.text
    body = response.json()
    coverage = body["collection_coverage"]
    assert coverage["freshness"] == "previous_generation"
    assert coverage["refresh_status"] == "building"
    assert coverage["as_of"] == store._generation_created_at(TENANT, old)
    assert body["snapshot_generation"] in (None, old.removeprefix("current-estate:"))
    assert "new-package" not in response.text, "a previous-generation response leaked the new generation"

    assert await_current_build(store, TENANT, seconds=10) not in (None, old)
    fresh = empty_estate_client.get(path.replace("old-package", "new-package"), headers=headers)
    assert fresh.status_code == 200, fresh.text
    assert "freshness" not in (fresh.json().get("collection_coverage") or {})
