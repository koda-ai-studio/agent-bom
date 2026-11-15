"""The PostgreSQL copy child yields to graph and findings reads the API has in flight, within caps."""

from __future__ import annotations

import json
import os
import stat

import pytest

from agent_bom.api import current_graph_pg_copy_child as child
from agent_bom.api import read_gauge
from agent_bom.api.read_gauge import CopyThrottle
from tests.test_current_graph_pg_copy_child import FIELDS


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0
        self.slept = 0.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds
        self.slept += seconds


@pytest.fixture()
def gauge(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "state"))
    read_gauge.reset_for_tests()
    yield read_gauge
    read_gauge.reset_for_tests()


def _throttle(path: str | None, clock: _Clock, **caps: float) -> CopyThrottle:
    return CopyThrottle(path, clock=clock.monotonic, sleep=clock.sleep, **caps)


def test_only_graph_and_findings_reads_count(gauge) -> None:
    assert gauge.counts("/v1/graph")
    assert gauge.counts("/v1/graph/search")
    assert gauge.counts("/v1/findings")
    assert not gauge.counts("/v1/results/push/abc")
    assert not gauge.counts("/v1/graphs-unrelated")
    assert not gauge.counts("/health")


def test_the_child_sees_the_parents_in_flight_count(gauge) -> None:
    path = gauge.gauge_path()
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600, "the gauge file is private"
    reader = CopyThrottle(path)
    assert reader.readers() == 0
    gauge.enter()
    gauge.enter()
    assert reader.readers() == 2
    gauge.leave()
    assert reader.readers() == 1
    gauge.leave()
    assert reader.readers() == 0
    # A read that began before the gauge existed is still counted once it is created.
    read_gauge.reset_for_tests()
    gauge.enter()
    assert CopyThrottle(gauge.gauge_path()).readers() == 1
    gauge.leave()


def test_throttle_pauses_while_reads_are_in_flight_and_not_when_idle(gauge) -> None:
    path, clock = gauge.gauge_path(), _Clock()
    throttle = _throttle(path, clock, batch_cap=0.5, total_cap=30.0)
    assert throttle.pause() == 0.0
    assert clock.slept == 0.0, "an idle API must not slow the copy"
    gauge.enter()
    paused = throttle.pause()
    gauge.leave()
    assert paused == pytest.approx(0.5)
    assert clock.slept == pytest.approx(0.5)


def test_throttle_resumes_as_soon_as_reads_finish(gauge) -> None:
    path, clock = gauge.gauge_path(), _Clock()
    gauge.enter()
    finished = []

    def sleep(seconds: float) -> None:
        clock.sleep(seconds)
        if clock.now >= 0.05 and not finished:
            finished.append(True)
            gauge.leave()

    throttle = CopyThrottle(path, clock=clock.monotonic, sleep=sleep, batch_cap=0.5, total_cap=30.0)
    assert 0.04 <= throttle.pause() <= 0.07


def test_total_pause_cap_holds_under_constant_reads(gauge) -> None:
    path, clock = gauge.gauge_path(), _Clock()
    throttle = _throttle(path, clock, batch_cap=0.5, total_cap=2.0)
    gauge.enter()
    try:
        for _ in range(100):
            throttle.pause()
    finally:
        gauge.leave()
    assert throttle.paused_seconds == pytest.approx(2.0, abs=0.011)
    assert clock.slept == pytest.approx(2.0, abs=0.011)


def test_no_gauge_or_an_unreadable_gauge_never_pauses(tmp_path) -> None:
    clock = _Clock()
    assert _throttle(None, clock).pause() == 0.0
    assert _throttle(str(tmp_path / "missing"), clock).pause() == 0.0
    (tmp_path / "short").write_bytes(b"\x01")
    assert _throttle(str(tmp_path / "short"), clock).pause() == 0.0
    assert clock.slept == 0.0


@pytest.mark.parametrize(("setting", "enabled"), [(None, False), ("0", False), ("1", True), ("true", True)])
def test_the_child_request_names_the_gauge_only_when_the_throttle_is_on(gauge, tmp_path, monkeypatch, setting, enabled) -> None:
    """Off by default: the throttle lengthens the build and, at 5,000 agents, the first findings read with it."""
    if setting is None:
        monkeypatch.delenv("AGENT_BOM_PG_COPY_THROTTLE", raising=False)
    else:
        monkeypatch.setenv("AGENT_BOM_PG_COPY_THROTTLE", setting)
    seen: dict[str, bytes] = {}

    class FakeProcess:
        returncode = child.EXIT_COPIED
        pid = 1

        def __init__(self, args, **kwargs):
            pass

        def communicate(self, payload=None, timeout=None):
            seen["payload"] = payload
            return b"", b""

    monkeypatch.setattr(child.subprocess, "Popen", FakeProcess)
    assert child.copy_in_child(str(tmp_path / "projection.db"), **FIELDS) is True
    request = json.loads(seen["payload"])
    if enabled:
        assert request["read_gauge"] == gauge.gauge_path()
    else:
        assert request["read_gauge"] == ""
        assert gauge._gauge is None, "no gauge file is created while the throttle is off"


def test_the_middleware_counts_estate_reads_for_their_duration(gauge) -> None:
    import asyncio

    from agent_bom.api import foreground_activity

    observed: list[int] = []
    reader = CopyThrottle(gauge.gauge_path())

    async def app(scope, receive, send):
        observed.append(reader.readers())

    async def admit(app_, scope, receive, send):
        await app_(scope, receive, send)

    import agent_bom.api.heavy_read_gate as gate

    original = gate.admit
    gate.admit = admit
    try:
        middleware = foreground_activity.ForegroundActivityMiddleware(app)
        asyncio.run(middleware({"type": "http", "path": "/v1/graph"}, None, None))
        asyncio.run(middleware({"type": "http", "path": "/v1/results/push/x"}, None, None))
    finally:
        gate.admit = original
    assert observed == [1, 0]
    assert reader.readers() == 0


@pytest.mark.parametrize(
    ("stdout", "expected"),
    [(b'{"paused_seconds": 1.25}\n', 1.25), (b"", 0.0), (b"not json\n", 0.0), (b'{"other": 1}\n', 0.0), (b"[]\n", 0.0)],
)
def test_the_childs_pause_receipt_is_read_defensively(stdout, expected) -> None:
    assert child._paused_seconds(stdout) == expected


def test_a_read_waiting_on_the_build_does_not_hold_the_build_back(gauge, monkeypatch) -> None:
    """A cold read waits for the build; counting it would make the copy yield to its own waiter."""
    import threading

    from agent_bom.api import current_graph_builds

    reader = CopyThrottle(gauge.gauge_path())
    seen: list[int] = []
    release = threading.Event()

    class Store:
        def _current_id(self, tenant):
            seen.append(reader.readers())
            release.set()
            return "generation"

    queue = current_graph_builds.CurrentBuildQueue()
    monkeypatch.setattr(current_graph_builds, "_QUEUE", queue)
    try:
        with gauge.counted_read():
            assert reader.readers() == 1
            assert current_graph_builds.await_current_build(Store(), "tenant", seconds=5) == "generation"
            assert reader.readers() == 1, "the read counts again once it stops waiting"
        assert reader.readers() == 0
    finally:
        queue.executor.shutdown(wait=True)
    assert seen == [0], "while the read waited on the build it was not counted"


def test_an_uncounted_caller_waiting_on_the_build_changes_nothing(gauge) -> None:
    reader = CopyThrottle(gauge.gauge_path())
    gauge.enter()  # another request in flight
    try:
        with gauge.waiting_on_build():
            assert reader.readers() == 1
    finally:
        gauge.leave()
