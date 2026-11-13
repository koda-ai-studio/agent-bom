"""Commit bursts: one running rebuild per tenant plus at most one trailing rebuild.

A commit that lands while the tenant's rebuild runs must not be absorbed by
that build: it read the older evidence. Without a trailing rebuild the next
reader pays for the build on the request path.
"""

from __future__ import annotations

import threading

from agent_bom.api import current_graph_builds
from agent_bom.api.current_graph_builds import CurrentBuildQueue


class _Store:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.release = threading.Event()
        self.started = threading.Event()
        self.lock = threading.Lock()

    def prepare_current(self, tenant: str, *, seconds: float) -> bool:  # pragma: no cover - capability marker
        return True

    def _current_id(self, tenant: str) -> str:
        with self.lock:
            self.calls.append(tenant)
            first = len(self.calls) == 1
        self.started.set()
        if first:
            assert self.release.wait(10)
        return f"current:{tenant}:{len(self.calls)}"


def _queue(monkeypatch) -> CurrentBuildQueue:
    queue = CurrentBuildQueue(workers=2, capacity=4)
    monkeypatch.setattr(current_graph_builds, "_QUEUE", queue)
    return queue


def test_commit_during_running_rebuild_queues_exactly_one_trailing_rebuild(monkeypatch) -> None:
    queue = _queue(monkeypatch)
    store = _Store()
    try:
        assert current_graph_builds.schedule_current_rebuild(store, "tenant-a")
        assert store.started.wait(5)
        for _ in range(5):
            assert current_graph_builds.schedule_current_rebuild(store, "tenant-a")
        store.release.set()
        assert queue.wait_idle(10)
        assert store.calls == ["tenant-a", "tenant-a"]
    finally:
        store.release.set()
        queue.executor.shutdown(wait=True)


def test_commit_before_build_starts_needs_no_trailing_rebuild(monkeypatch) -> None:
    queue = _queue(monkeypatch)
    store = _Store()
    store.release.set()
    try:
        assert current_graph_builds.schedule_current_rebuild(store, "tenant-a")
        assert queue.wait_idle(10)
        assert current_graph_builds.schedule_current_rebuild(store, "tenant-a")
        assert queue.wait_idle(10)
        assert store.calls == ["tenant-a", "tenant-a"]
    finally:
        queue.executor.shutdown(wait=True)


def test_trailing_rebuild_is_per_tenant(monkeypatch) -> None:
    queue = _queue(monkeypatch)
    store = _Store()
    try:
        assert current_graph_builds.schedule_current_rebuild(store, "tenant-a")
        assert store.started.wait(5)
        assert current_graph_builds.schedule_current_rebuild(store, "tenant-b")
        store.release.set()
        assert queue.wait_idle(10)
        assert sorted(store.calls) == ["tenant-a", "tenant-b"]
    finally:
        store.release.set()
        queue.executor.shutdown(wait=True)


def test_reader_join_does_not_add_a_trailing_rebuild(monkeypatch) -> None:
    queue = _queue(monkeypatch)
    store = _Store()
    try:
        assert current_graph_builds.schedule_current_rebuild(store, "tenant-a")
        assert store.started.wait(5)
        assert queue.submit(store, "tenant-a") is not None
        store.release.set()
        assert queue.wait_idle(10)
        assert store.calls == ["tenant-a"]
    finally:
        store.release.set()
        queue.executor.shutdown(wait=True)
