"""Current-estate reads share the projection; only resolve/retire is exclusive."""

import threading
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout

import pytest

from agent_bom.api.current_graph import CurrentGraphStore
from tests.api import test_current_graph_estate as estate_helpers

estate = estate_helpers.estate
record = estate_helpers.record
TENANT = "history-tenant"


def _block_projection_reads(store: CurrentGraphStore, name: str) -> tuple[threading.Event, threading.Event]:
    entered, release = threading.Event(), threading.Event()
    reader = getattr(store._projection_store, name)

    def blocked(*args, **kwargs):
        entered.set()
        assert release.wait(10), "test never released the blocked reader"
        return reader(*args, **kwargs)

    setattr(store._projection_store, name, blocked)
    return entered, release


def test_concurrent_current_reads_do_not_queue_behind_a_slow_read(estate):
    record(estate, 8, "repo-a", "package-a")
    store = CurrentGraphStore(estate[1], estate[0])
    generation = store.latest_snapshot_id(tenant_id=TENANT)
    entered, release = _block_projection_reads(store, "attack_paths")
    with ThreadPoolExecutor(max_workers=2) as workers:
        slow = workers.submit(store.attack_paths, tenant_id=TENANT)
        assert entered.wait(5)
        try:
            page = workers.submit(store.page_nodes, tenant_id=TENANT, limit=10).result(timeout=5)
            stats = workers.submit(store.snapshot_stats, tenant_id=TENANT).result(timeout=5)
        except FutureTimeout:
            pytest.fail("a current-estate read waited for an unrelated in-flight read")
        finally:
            release.set()
        slow.result(timeout=5)
    assert page[0] == generation
    assert [node.id for node in page[2]] == ["package-a"]
    assert stats["snapshot_generation"] == generation.removeprefix("current-estate:")


def test_retirement_waits_for_active_readers_of_the_old_generation(estate):
    record(estate, 8, "repo-a", "package-a")
    store = CurrentGraphStore(estate[1], estate[0])
    old = store.latest_snapshot_id(tenant_id=TENANT)
    entered, release = _block_projection_reads(store, "load_graph")
    with ThreadPoolExecutor(max_workers=2) as workers:
        reading_old = workers.submit(store.load_graph, tenant_id=TENANT)
        assert entered.wait(5)
        record(estate, 9, "repo-a", "package-b")
        replacing = workers.submit(store.snapshot_identity, tenant_id=TENANT, for_paging=True)
        with pytest.raises(FutureTimeout):
            replacing.result(timeout=0.5)
        release.set()
        old_graph = reading_old.result(timeout=5)
        new_identity = replacing.result(timeout=5)
    assert old_graph.scan_id == old
    assert set(old_graph.nodes) == {"package-a"}
    assert new_identity[0] != old
    assert set(store.load_graph(tenant_id=TENANT).nodes) == {"package-b"}


def _pause_before_build(
    store: CurrentGraphStore, thread_name: str, *, resume_timeout: float = 10
) -> tuple[threading.Event, threading.Event]:
    """Hold *thread_name* before it becomes the builder, after it has read the evidence fingerprint."""
    paused, resume = threading.Event(), threading.Event()
    building = store._building

    def gated(*args, **kwargs):
        if threading.current_thread().name == thread_name and not paused.is_set():
            paused.set()
            assert resume.wait(resume_timeout), "test never resumed the stale resolver"
        return building(*args, **kwargs)

    store._building = gated  # type: ignore[method-assign]
    return paused, resume


@pytest.fixture(params=["memory-jobs", "sqlite-jobs"])
def revisioned_estate(request, estate, tmp_path):
    if request.param == "memory-jobs":
        return estate
    from agent_bom.api.store import SQLiteJobStore

    # Durable job stores expose a mutation revision; the stale resolver used to
    # fail its own read with a 409 there instead of retiring the newer generation.
    return SQLiteJobStore(str(tmp_path / "jobs.db")), estate[1]


def test_a_resolver_that_read_older_evidence_never_retires_the_newer_generation(revisioned_estate):
    estate = revisioned_estate
    record(estate, 8, "repo-a", "package-a")
    store = CurrentGraphStore(estate[1], estate[0])
    paused, resume = _pause_before_build(store, "stale-resolver")
    stale: list[str] = []
    resolver = threading.Thread(target=lambda: stale.append(store._resolve_current_id(TENANT)), name="stale-resolver")
    resolver.start()
    assert paused.wait(5)
    # New evidence lands and a reader resolves it while the first resolver is still waiting.
    record(estate, 9, "repo-b", "package-b")
    fresh = store._resolve_current_id(TENANT)
    resume.set()
    resolver.join(5)
    assert not resolver.is_alive()

    assert store._projection_store.snapshot_identity(tenant_id=TENANT, scan_id=fresh)[1], "newer generation was retired"
    assert stale == [fresh]
    assert set(store.load_graph(tenant_id=TENANT).nodes) == {"package-a", "package-b"}
