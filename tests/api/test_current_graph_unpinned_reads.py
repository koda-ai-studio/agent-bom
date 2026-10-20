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


def test_reads_serve_the_previous_generation_while_a_rebuild_is_in_flight(revisioned_estate):
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
