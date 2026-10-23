"""Unpinned current-estate reads serve one consistent generation while new evidence lands.

A read without a generation pin must never answer 409 because a concurrent
push promoted or retired a projection, and it must not wait for a rebuild when
an older consistent generation is still live. Pinned continuations keep their
409 contract (see ``test_replay_changes_generation_and_rejects_stale_continuation``).
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from starlette.exceptions import HTTPException

from agent_bom.api.current_graph import CurrentGraphStore
from agent_bom.api.finding_read_context import finding_read_scope
from tests.api import test_current_graph_estate as estate_helpers

estate = estate_helpers.estate
record = estate_helpers.record
TENANT = "history-tenant"


@pytest.fixture(params=["memory-jobs", "sqlite-jobs"])
def revisioned_estate(request, estate, tmp_path):
    if request.param == "memory-jobs":
        return estate
    from agent_bom.api.store import SQLiteJobStore

    return SQLiteJobStore(str(tmp_path / "jobs.db")), estate[1]


def _hold_materialize(store: CurrentGraphStore) -> tuple[threading.Event, threading.Event]:
    entered, release = threading.Event(), threading.Event()
    materialize = store._materialize

    def held(*args, **kwargs):
        entered.set()
        assert release.wait(10), "test never released the rebuild"
        return materialize(*args, **kwargs)

    store._materialize = held  # type: ignore[method-assign]
    return entered, release


def test_reads_serve_the_previous_generation_while_a_rebuild_is_in_flight(revisioned_estate, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_CURRENT_GRAPH_BUILD_WAIT_MS", "50")
    estate = revisioned_estate
    record(estate, 8, "repo-a", "package-a")
    store = CurrentGraphStore(estate[1], estate[0])
    old = store.latest_snapshot_id(tenant_id=TENANT)
    entered, release = _hold_materialize(store)
    record(estate, 9, "repo-b", "package-b")
    with ThreadPoolExecutor(max_workers=2) as workers:
        building = workers.submit(store.latest_snapshot_id, tenant_id=TENANT)
        assert entered.wait(5)
        try:
            reader = workers.submit(lambda: (store.latest_snapshot_id(tenant_id=TENANT), set(store.load_graph(tenant_id=TENANT).nodes)))
            served, nodes = reader.result(timeout=5)
        finally:
            release.set()
        new = building.result(timeout=10)
    assert served == old
    assert nodes == {"package-a"}
    assert new != old
    assert set(store.load_graph(tenant_id=TENANT).nodes) == {"package-a", "package-b"}


def test_a_scoped_read_keeps_its_generation_when_another_request_promotes(revisioned_estate):
    estate = revisioned_estate
    record(estate, 8, "repo-a", "package-a")
    store = CurrentGraphStore(estate[1], estate[0])
    first_page_read, promoted = threading.Event(), threading.Event()
    seen: list[object] = []

    def request() -> None:
        with finding_read_scope():
            identity = store.snapshot_identity(tenant_id=TENANT, for_paging=True)
            first_page_read.set()
            assert promoted.wait(10)
            try:
                graph = store.load_graph(tenant_id=TENANT)
                seen.append((identity[0], graph.scan_id, set(graph.nodes)))
            except HTTPException as exc:
                seen.append(exc.status_code)

    reader = threading.Thread(target=request)
    reader.start()
    assert first_page_read.wait(5)
    old = store._cache[TENANT][2]
    record(estate, 9, "repo-a", "package-b")
    new = store.latest_snapshot_id(tenant_id=TENANT)
    promoted.set()
    reader.join(10)
    assert new != old
    assert seen == [(old, old, {"package-a"})]
    # The pin ends with the request; the next promotion retires the old generation.
    record(estate, 10, "repo-a", "package-c")
    store.latest_snapshot_id(tenant_id=TENANT)
    assert not store._projection_store.snapshot_identity(tenant_id=TENANT, scan_id=old)[1]


def test_evidence_landing_during_a_rebuild_serves_a_consistent_view_not_a_conflict(revisioned_estate):
    estate = revisioned_estate
    record(estate, 8, "repo-a", "package-a")
    store = CurrentGraphStore(estate[1], estate[0])
    store.latest_snapshot_id(tenant_id=TENANT)
    record(estate, 9, "repo-b", "package-b")
    materialize = store._materialize
    landed = []

    def push_mid_build(*args, **kwargs):
        if not landed:
            landed.append(record(estate, 10, "repo-c", "package-c"))
        return materialize(*args, **kwargs)

    store._materialize = push_mid_build  # type: ignore[method-assign]
    nodes = set(store.load_graph(tenant_id=TENANT).nodes)
    assert nodes in ({"package-a", "package-b"}, {"package-a", "package-b", "package-c"})
    assert set(store.load_graph(tenant_id=TENANT).nodes) == {"package-a", "package-b", "package-c"}


def test_rebuild_requested_while_iterating_promotes_without_retiring_the_iterated_generation(estate):
    record(estate, 8, "repo-a", "package-a")
    store = CurrentGraphStore(estate[1], estate[0])
    old = store.latest_snapshot_id(tenant_id=TENANT)
    nodes = store.iter_nodes(tenant_id=TENANT)
    first = next(nodes)
    record(estate, 9, "repo-a", "package-b")
    graph = store.load_graph(tenant_id=TENANT)
    assert set(graph.nodes) == {"package-b"}
    assert "package-a" in str(getattr(first, "id", first))
    assert list(nodes) == []
    assert store._projection_store.snapshot_identity(tenant_id=TENANT, scan_id=old)[1], "iterated generation retired mid-read"


def test_concurrent_unpinned_reads_never_conflict_during_pushes(estate):
    """Soak: scoped first-page style reads across 50 promotions see whole generations only."""
    record(estate, 8, "repo-0", "package-0")
    store = CurrentGraphStore(estate[1], estate[0])
    store.latest_snapshot_id(tenant_id=TENANT)
    stop = threading.Event()
    failures: list[object] = []
    reads = [0]

    def read_loop() -> None:
        while not stop.is_set():
            try:
                with finding_read_scope():
                    identity = store.snapshot_identity(tenant_id=TENANT, for_paging=True)
                    graph = store.load_graph(tenant_id=TENANT)
                    again = store.snapshot_identity(tenant_id=TENANT, for_paging=True)
                if graph.scan_id != identity[0] or again != identity:
                    failures.append(("mixed generations", identity, graph.scan_id, again))
                expected = {f"package-{index}" for index in range(len(graph.nodes))}
                if set(graph.nodes) != expected:
                    failures.append(("partial generation", sorted(graph.nodes)))
                reads[0] += 1
            except HTTPException as exc:
                failures.append((exc.status_code, exc.detail))

    readers = [threading.Thread(target=read_loop) for _ in range(3)]
    for thread in readers:
        thread.start()
    try:
        for index in range(1, 51):
            record(estate, 8, f"repo-{index}", f"package-{index}")
            store.latest_snapshot_id(tenant_id=TENANT)
    finally:
        stop.set()
        for thread in readers:
            thread.join(30)
    assert not failures, failures[:5]
    assert reads[0] > 0
    assert set(store.load_graph(tenant_id=TENANT).nodes) == {f"package-{index}" for index in range(51)}


def test_a_read_waits_briefly_for_an_in_flight_build_of_its_own_evidence(estate, monkeypatch):
    """Read-your-writes: a background warm-up that starts the rebuild must not make the next read stale."""
    monkeypatch.setenv("AGENT_BOM_CURRENT_GRAPH_BUILD_WAIT_MS", "5000")
    record(estate, 8, "repo-a", "package-a")
    store = CurrentGraphStore(estate[1], estate[0])
    store.latest_snapshot_id(tenant_id=TENANT)
    entered, release = _hold_materialize(store)
    record(estate, 9, "repo-b", "package-b")
    with ThreadPoolExecutor(max_workers=2) as workers:
        warming = workers.submit(store.latest_snapshot_id, tenant_id=TENANT)
        assert entered.wait(5)
        reader = workers.submit(lambda: set(store.load_graph(tenant_id=TENANT).nodes))
        threading.Timer(0.2, release.set).start()
        nodes = reader.result(timeout=10)
        warming.result(timeout=10)
    assert nodes == {"package-a", "package-b"}


def _retire_every_resolved_generation(store: CurrentGraphStore) -> None:
    """Another worker retires each generation right after this reader resolves it."""
    resolve = store._resolved_id

    def rotating(tenant: str) -> str:
        identity = resolve(tenant)
        store._projection_store.delete_snapshot(tenant_id=tenant, scan_id=identity)
        return identity

    store._resolved_id = rotating  # type: ignore[method-assign]


@pytest.mark.parametrize("read", ["latest_snapshot_id", "load_graph"])
def test_unpinned_read_that_never_sees_a_live_generation_is_retryable_not_a_conflict(estate, read):
    record(estate, 8, "repo-a", "package-a")
    store = CurrentGraphStore(estate[1], estate[0])
    _retire_every_resolved_generation(store)
    with pytest.raises(HTTPException) as exc:
        getattr(store, read)(tenant_id=TENANT)
    assert exc.value.status_code == 503
    assert exc.value.headers == {"Retry-After": "1"}
    assert exc.value.detail["code"] == "current_estate_generation_rotating"
    assert exc.value.detail["message"]


def test_get_graph_answers_rotation_with_503_and_a_stale_pin_with_409(estate):
    from starlette.testclient import TestClient

    from agent_bom.api import stores
    from agent_bom.api.server import app

    record(estate, 8, "repo-a", "package-a", tenant="default")
    client = TestClient(app)
    first = client.get("/v1/graph", params={"limit": 10})
    assert first.status_code == 200, first.text
    generation = first.json()["snapshot_generation"]
    record(estate, 9, "repo-a", "package-b", tenant="default")
    stale = client.get("/v1/graph", params={"limit": 10, "offset": 10, "snapshot_generation": generation})
    assert stale.status_code == 409
    assert "Retry-After" not in stale.headers

    _retire_every_resolved_generation(stores._get_graph_store())  # type: ignore[arg-type]
    rotating = client.get("/v1/graph", params={"limit": 10})
    assert rotating.status_code == 503
    assert rotating.headers["Retry-After"] == "1"
    body = rotating.json()
    assert body["error"]["code"] == "SERVICE_UNAVAILABLE"
    assert body["error"]["details"]["code"] == "current_estate_generation_rotating"


def test_openapi_documents_the_retryable_rotation_response_on_get_graph():
    from agent_bom.api.server import app

    response = app.openapi()["paths"]["/v1/graph"]["get"]["responses"]["503"]
    assert "Retry-After" in response["headers"]
    assert "current_estate_generation_rotating" in response["description"]


def _replay_source_during_assembly(estate, *, times: int) -> list[int]:
    """Re-push the source scan while the projection loads it, so its revision moves mid-assembly."""
    graph_store = estate[1]
    load = graph_store.load_graph
    replays: list[int] = []

    def replaying(*args, **kwargs):
        graph = load(*args, **kwargs)
        if kwargs.get("scan_id") and len(replays) < times:
            replays.append(1)
            record(estate, 8, "repo-a", f"package-replay-{len(replays)}", tenant=kwargs.get("tenant_id", TENANT))
        return graph

    graph_store.load_graph = replaying  # type: ignore[method-assign]
    return replays


def test_evidence_replaced_during_assembly_rebuilds_from_fresh_evidence_not_a_conflict(estate):
    record(estate, 8, "repo-a", "package-a")
    store = CurrentGraphStore(estate[1], estate[0])
    replays = _replay_source_during_assembly(estate, times=1)
    graph = store.load_graph(tenant_id=TENANT)
    assert replays == [1]
    assert set(graph.nodes) == {"package-replay-1"}


def test_evidence_that_keeps_moving_during_assembly_is_retryable_not_a_conflict(estate):
    record(estate, 8, "repo-a", "package-a")
    store = CurrentGraphStore(estate[1], estate[0])
    _replay_source_during_assembly(estate, times=100)
    with pytest.raises(HTTPException) as exc:
        store.load_graph(tenant_id=TENANT)
    assert exc.value.status_code == 503
    assert exc.value.headers == {"Retry-After": "1"}
    assert exc.value.detail["code"] == "current_estate_generation_rotating"


def test_get_graph_answers_assembly_churn_with_503_retry_after(estate):
    from starlette.testclient import TestClient

    from agent_bom.api.server import app

    record(estate, 8, "repo-a", "package-a", tenant="default")
    _replay_source_during_assembly(estate, times=100)
    response = TestClient(app).get("/v1/graph", params={"limit": 10})
    assert response.status_code == 503, response.text
    assert response.headers["Retry-After"] == "1"
    assert response.json()["error"]["details"]["code"] == "current_estate_generation_rotating"
