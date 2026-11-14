"""A push's current-graph rebuild starts at commit and runs before, never beside, the post-commit warm-ups."""

from __future__ import annotations

import threading
import time

import pytest

from agent_bom.api import current_graph_builds, graph_warmup_slot
from agent_bom.api.current_graph_builds import CurrentBuildQueue


class _BlockingStore:
    """Stands in for the current-graph wrapper: a build that finishes when the test says so."""

    def __init__(self) -> None:
        self.release = threading.Event()
        self.started = threading.Event()
        self.built: list[str] = []

    def prepare_current(self, tenant, *, seconds):  # pragma: no cover - presence marks a current-graph store
        raise AssertionError("commit scheduling must not wait on the build")

    def _current_id(self, tenant: str) -> str:
        self.started.set()
        assert self.release.wait(10)
        self.built.append(tenant)
        return f"current-estate:{tenant}"


@pytest.fixture
def queue(monkeypatch):
    private = CurrentBuildQueue(workers=2)
    monkeypatch.setattr(current_graph_builds, "_QUEUE", private)
    yield private
    private.executor.shutdown(wait=False, cancel_futures=True)


def _enter_slot_in_thread() -> tuple[threading.Thread, threading.Event]:
    entered = threading.Event()

    def warm() -> None:
        with graph_warmup_slot.warmup_slot():
            entered.set()

    thread = threading.Thread(target=warm, daemon=True)
    thread.start()
    return thread, entered


def test_a_warm_up_waits_for_an_in_flight_current_graph_build(queue):
    store = _BlockingStore()
    assert queue.submit(store, "tenant-a") is not None
    assert store.started.wait(5)

    thread, entered = _enter_slot_in_thread()
    assert not entered.wait(0.3), "a warm-up loaded its graph beside a current-graph build"
    store.release.set()
    assert entered.wait(5)
    thread.join(5)
    assert store.built == ["tenant-a"]


def test_a_warm_up_stops_yielding_past_its_bound(queue, monkeypatch):
    monkeypatch.setattr(graph_warmup_slot, "BUILD_YIELD_SECONDS", 0.05)
    store = _BlockingStore()
    queue.submit(store, "tenant-a")
    assert store.started.wait(5)
    began = time.monotonic()
    thread, entered = _enter_slot_in_thread()
    try:
        assert entered.wait(5)
        assert time.monotonic() - began < 2
    finally:
        store.release.set()
        thread.join(5)


def test_an_idle_queue_never_delays_a_warm_up(queue):
    thread, entered = _enter_slot_in_thread()
    assert entered.wait(1)
    thread.join(5)


def test_a_push_commit_queues_the_current_graph_rebuild_without_waiting(queue, monkeypatch):
    from agent_bom.api.routes import observability

    store = _BlockingStore()
    monkeypatch.setattr(observability, "_get_graph_store", lambda: store)
    began = time.monotonic()
    assert observability.schedule_current_graph_rebuild("tenant-a") is True
    assert time.monotonic() - began < 0.5
    assert store.started.wait(5)
    # The running build read the older evidence: further commits collapse into
    # exactly one trailing rebuild, never one per commit.
    for _ in range(3):
        assert observability.schedule_current_graph_rebuild("tenant-a") is True
    store.release.set()
    assert queue.wait_idle(5)
    assert store.built == ["tenant-a", "tenant-a"]


def test_a_store_without_current_graphs_is_left_alone(queue):
    class Explicit:
        pass

    assert current_graph_builds.schedule_current_rebuild(Explicit(), "tenant-a") is False
    assert current_graph_builds.schedule_current_rebuild(_BlockingStore(), "") is False
    assert queue.wait_idle(0)


def test_the_rebuild_is_scheduled_before_the_exec_warm_up_on_every_push_commit():
    from agent_bom.api import push_ingest_worker
    from agent_bom.api.exec_read_prewarm import schedule_exec_prewarm
    from agent_bom.api.routes import observability

    listeners = push_ingest_worker._COMMIT_LISTENERS
    rebuild = listeners.index(observability.schedule_current_graph_rebuild)
    assert rebuild < listeners.index(schedule_exec_prewarm)


def test_a_warm_up_waits_while_an_ingest_still_holds_its_graph(queue):
    work = graph_warmup_slot.foreground_graph_work()
    work.__enter__()
    thread, entered = _enter_slot_in_thread()
    try:
        assert not entered.wait(0.3), "a warm-up loaded a graph while an ingest still held its own"
    finally:
        work.__exit__(None, None, None)
    assert entered.wait(5)
    thread.join(5)


def test_the_yield_bound_covers_foreground_work_too(queue, monkeypatch):
    monkeypatch.setattr(graph_warmup_slot, "BUILD_YIELD_SECONDS", 0.05)
    with graph_warmup_slot.foreground_graph_work():
        thread, entered = _enter_slot_in_thread()
        assert entered.wait(5)
    thread.join(5)


def test_push_ingest_is_foreground_from_graph_persist_until_the_rebuild_is_queued(monkeypatch):
    """Commit hooks start warm-ups during persist; they must not run before the job commit hands off the rebuild."""
    from agent_bom.api import push_ingest_worker
    from agent_bom.api.models import JobStatus, ScanJob, ScanRequest

    job = ScanJob(job_id="job-1", tenant_id="tenant-a", created_at="", request=ScanRequest(), status=JobStatus.PENDING)
    job.result = {"pushed": True, "scan_id": "job-1"}
    seen: dict[str, bool] = {}

    class Store:
        def put(self, stored):
            seen["store"] = graph_warmup_slot.foreground_active()

    monkeypatch.setattr(push_ingest_worker, "_get_store", Store)
    monkeypatch.setattr(push_ingest_worker, "read_job_riding_out_blips", lambda store, current: current)
    monkeypatch.setattr(push_ingest_worker, "_graph_snapshot_exists", lambda tenant, scan: False)
    monkeypatch.setattr(
        push_ingest_worker, "_persist_push_graph", lambda *a, **k: seen.__setitem__("persist", graph_warmup_slot.foreground_active())
    )
    monkeypatch.setattr(push_ingest_worker, "_record_push_trend", lambda *a, **k: None)
    monkeypatch.setattr(
        push_ingest_worker, "notify_push_committed", lambda tenant: seen.__setitem__("notify", graph_warmup_slot.foreground_active())
    )

    push_ingest_worker.run_push_ingest(job)

    assert seen == {"persist": True, "store": True, "notify": True}
    assert job.status == JobStatus.DONE
    assert graph_warmup_slot.foreground_active() is False
