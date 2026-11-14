"""Post-commit warm-ups step aside while requests are in flight; requests never wait on themselves.

A CPU-bound thread beside a warm graph read took it from 95 ms to 9.4 s on
Python's GIL. After a 5,000-agent push on Postgres the roll-up warm-up loaded
the whole new projection into Python and every read in the next minute paid
for it. Warm-up loops now pause at bounded yield points while requests are in
flight; other threads iterate at full speed.
"""

from __future__ import annotations

import threading
import time

from agent_bom.api import foreground_activity, graph_warmup_slot
from agent_bom.core import background_yield


def _iterate_in_thread(*, background: bool, rows: int = 400, every: int = 10) -> float:
    elapsed: list[float] = []

    def run() -> None:
        started = time.monotonic()
        if background:
            with background_yield.background_work():
                list(background_yield.yielding(range(rows), every=every))
        else:
            list(background_yield.yielding(range(rows), every=every))
        elapsed.append(time.monotonic() - started)

    thread = threading.Thread(target=run)
    thread.start()
    thread.join(10)
    return elapsed[0]


def test_background_work_pauses_while_requests_are_in_flight(monkeypatch) -> None:
    monkeypatch.setattr(background_yield, "MAX_PAUSE_SECONDS", 0.02)
    foreground_activity.reset()
    foreground_activity._enter()
    try:
        # 40 yield points x up to 20 ms each.
        assert _iterate_in_thread(background=True) >= 0.4
    finally:
        foreground_activity._leave()


def test_background_work_runs_freely_when_no_request_is_in_flight(monkeypatch) -> None:
    monkeypatch.setattr(background_yield, "MAX_PAUSE_SECONDS", 0.02)
    foreground_activity.reset()
    assert _iterate_in_thread(background=True) < 0.2


def test_request_threads_never_pause(monkeypatch) -> None:
    monkeypatch.setattr(background_yield, "MAX_PAUSE_SECONDS", 0.02)
    foreground_activity.reset()
    foreground_activity._enter()
    try:
        assert _iterate_in_thread(background=False) < 0.2
    finally:
        foreground_activity._leave()


def test_each_pause_is_bounded_so_constant_traffic_cannot_starve_a_warm_up(monkeypatch) -> None:
    monkeypatch.setattr(background_yield, "MAX_PAUSE_SECONDS", 0.01)
    foreground_activity.reset()
    foreground_activity._enter()
    try:
        assert _iterate_in_thread(background=True) < 1.5
    finally:
        foreground_activity._leave()


def test_background_pauses_never_read_a_patched_time_module(monkeypatch) -> None:
    """A test that fakes ``time.monotonic`` with a finite iterator must not lose readings to a warm-up thread."""
    import time

    monkeypatch.setattr(background_yield, "MAX_PAUSE_SECONDS", 0.02)
    real = time.monotonic
    readers: list[str] = []

    def recording() -> float:
        readers.append(threading.current_thread().name)
        return real()

    foreground_activity.reset()
    foreground_activity._enter()
    paused = threading.Event()

    def run() -> None:
        with background_yield.background_work():
            list(background_yield.yielding(range(40), every=10))
        paused.set()

    monkeypatch.setattr(time, "monotonic", recording)
    try:
        worker = threading.Thread(target=run, name="background-under-test")
        worker.start()
        assert paused.wait(5)
        worker.join(5)
    finally:
        monkeypatch.undo()
        foreground_activity._leave()
    assert "background-under-test" not in readers


def test_the_warm_up_slot_marks_its_thread_as_background() -> None:
    seen: list[bool] = []

    def run() -> None:
        with graph_warmup_slot.warmup_slot():
            seen.append(background_yield.in_background())
        seen.append(background_yield.in_background())

    thread = threading.Thread(target=run)
    thread.start()
    thread.join(10)
    assert seen == [True, False]


def test_current_graph_builds_run_as_background_work() -> None:
    """The post-push build is the heaviest background loop; its yield points must be live."""
    from agent_bom.api.current_graph_builds import CurrentBuildQueue

    seen: list[bool] = []

    class Store:
        def _current_id(self, tenant: str) -> str:
            seen.append(background_yield.in_background())
            return tenant

    queue = CurrentBuildQueue(workers=1, capacity=2)
    try:
        assert queue.submit(Store(), "alpha").result(timeout=5) == "alpha"
    finally:
        queue.executor.shutdown(wait=True)
    assert seen == [True]


def test_a_request_waiting_on_background_work_does_not_hold_it_back() -> None:
    """A read blocked on the build it needs must not make that build pause for it."""
    foreground_activity.reset()
    foreground_activity._enter()
    try:
        assert foreground_activity.requests_in_flight()
        with foreground_activity.awaiting_background():
            assert foreground_activity.requests_in_flight(), "a waiter outside a request masks nothing"
        marker = foreground_activity._in_request.set(True)
        with foreground_activity.awaiting_background():
            assert not foreground_activity.requests_in_flight()
            foreground_activity._enter()
            try:
                assert foreground_activity.requests_in_flight(), "another request still counts"
            finally:
                foreground_activity._leave()
        foreground_activity._in_request.reset(marker)
        assert foreground_activity.requests_in_flight()
    finally:
        foreground_activity._leave()
    assert not foreground_activity.requests_in_flight()


def test_awaiting_a_build_stands_aside_for_it(monkeypatch) -> None:
    from agent_bom.api import current_graph_builds

    seen: list[bool] = []

    class Store:
        def _current_id(self, tenant: str) -> str:
            deadline = time.monotonic() + 2
            while foreground_activity.requests_in_flight() and time.monotonic() < deadline:
                time.sleep(0.01)
            seen.append(foreground_activity.requests_in_flight())
            return tenant

    queue = current_graph_builds.CurrentBuildQueue(workers=1, capacity=2)
    monkeypatch.setattr(current_graph_builds, "_QUEUE", queue)
    foreground_activity.reset()
    foreground_activity._enter()
    marker = foreground_activity._in_request.set(True)
    try:
        assert current_graph_builds.await_current_build(Store(), "alpha", seconds=5) == "alpha"
        assert foreground_activity.requests_in_flight()
    finally:
        foreground_activity._in_request.reset(marker)
        foreground_activity._leave()
        queue.executor.shutdown(wait=True)
    assert seen == [False]


def test_sqlite_projection_writes_pause_between_batches(tmp_path, monkeypatch) -> None:
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.db import graph_store, graph_store_schema, graph_store_write
    from agent_bom.graph import EntityType, UnifiedEdge, UnifiedGraph, UnifiedNode
    from agent_bom.graph.types import RelationshipType

    pauses: list[str] = []
    monkeypatch.setattr(graph_store, "_graph_write_batch_size", lambda: 10)
    monkeypatch.setattr(graph_store_write, "pause_for_requests", lambda: pauses.append("nodes"))
    monkeypatch.setattr(graph_store_schema, "pause_for_requests", lambda: pauses.append("rows"))
    graph = UnifiedGraph(scan_id="scan-1", tenant_id="tenant-a")
    for index in range(30):
        graph.add_node(UnifiedNode(id=f"package:{index}", entity_type=EntityType.PACKAGE, label=f"p{index}"))
    for index in range(29):
        graph.add_edge(UnifiedEdge(source=f"package:{index}", target=f"package:{index + 1}", relationship=RelationshipType.DEPENDS_ON))
    SQLiteGraphStore(str(tmp_path / "graph.db")).save_graph(graph)
    assert pauses.count("nodes") >= 3
    assert pauses.count("rows") >= 3


def test_postgres_graph_load_yields_while_decoding_rows(monkeypatch) -> None:
    from tests.test_postgres_graph_streaming import _FakeCursor, _make_store, _RecordingConn

    node_rows = [
        (f"agent:{index}", "agent", f"Agent {index}", 1, 1, 1, "active", 1.0, "low", 2, "2026-07-19T00:00:00Z", "2026-07-19T00:00:00Z")
        + ({}, [], [], {})
        for index in range(1200)
    ]

    class _LoadConn(_RecordingConn):
        def execute(self, sql, params=None):
            low = " ".join(sql.strip().lower().split())
            if low.startswith("select created_at, analysis_status from graph_snapshots"):
                return _FakeCursor([("2026-07-19T00:00:00Z", None)])
            if "from graph_nodes" in low and low.startswith("select id, entity_type"):
                return _FakeCursor(node_rows)
            return super().execute(sql, params)

    pauses: list[int] = []
    monkeypatch.setattr(background_yield, "pause_for_requests", lambda: pauses.append(1))
    graph = _make_store(_LoadConn(), monkeypatch).load_graph(tenant_id="tenant-a", scan_id="scan-1")
    assert len(graph.nodes) == 1200
    assert len(pauses) >= 2
