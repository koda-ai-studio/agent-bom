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
