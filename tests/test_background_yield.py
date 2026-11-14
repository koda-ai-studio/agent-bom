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


def test_the_current_graph_rebuild_runs_at_full_speed() -> None:
    """Pausing the rebuild for requests stretched its contention across every read after a push.

    On a 4-vCPU runner at 5,000 agents on PostgreSQL that doubled the median graph
    read (0.76 s to 1.85 s), so the rebuild is not deferrable background work.
    """
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
    assert seen == [False]
