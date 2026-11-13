"""Concurrent misses on one cached row set fold it once.

An ingest commit bumps the job revision, so every findings reader in flight
misses the folded scan rows at the same moment. Each one used to rebuild the
same fold beside the others; the interpreter lock serialized them, so each
waited for all of them, and the post-commit warm-up competed with all of them.
A reader that misses while another reader is already building the same key
now waits for that build and shares its rows. A read the cache may not serve
(no input fingerprint) still builds its own rows.
"""

from __future__ import annotations

import threading
import time

import pytest

from agent_bom.api import finding_walk_cache

_NO_STORES: dict = {"hub": None, "job_store": None}
_KEY = ("t1", 90, None, None, "open", "effective_reach", "[]")
_FOLLOWER_ARRIVES = 0.3


@pytest.fixture(autouse=True)
def _fresh_cache():
    finding_walk_cache.clear()
    yield
    finding_walk_cache.clear()


@pytest.fixture(autouse=True)
def _revision(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(finding_walk_cache, "_revision", lambda tenant_id, hub, job_store: ("1", "0"))


class _SlowLoad:
    """The first call blocks until released, so a second reader arrives mid-build."""

    def __init__(self, *, fail_first: bool = False) -> None:
        self.calls = 0
        self.started = threading.Event()
        self.release = threading.Event()
        self.fail_first = fail_first
        self._lock = threading.Lock()

    def __call__(self) -> list[dict]:
        with self._lock:
            self.calls += 1
            call = self.calls
        if call == 1:
            self.started.set()
            assert self.release.wait(10)
            if self.fail_first:
                raise RuntimeError("leader failed")
        return [{"id": f"row-{call}"}]


def _race(read, load: _SlowLoad) -> list[object]:
    results: list[object] = [None, None]

    def run(slot: int) -> None:
        try:
            results[slot] = read()
        except RuntimeError as exc:
            results[slot] = exc

    leader = threading.Thread(target=run, args=(0,))
    leader.start()
    assert load.started.wait(10)
    follower = threading.Thread(target=run, args=(1,))
    follower.start()
    time.sleep(_FOLLOWER_ARRIVES)
    load.release.set()
    leader.join(10)
    follower.join(10)
    return results


def test_concurrent_misses_on_the_folded_rows_build_them_once() -> None:
    load = _SlowLoad()
    read = lambda: finding_walk_cache.reuse_rows(  # noqa: E731
        ("current_rows", None), tenant_id="t1", job_store=None, inputs=lambda: (("fp",), None), load=load
    )

    leader_rows, follower_rows = _race(read, load)

    assert load.calls == 1
    assert follower_rows is leader_rows == [{"id": "row-1"}]


def test_concurrent_first_pages_with_a_fingerprint_build_once() -> None:
    load = _SlowLoad()
    read = lambda: finding_walk_cache.walk_rows(  # noqa: E731
        _KEY, tenant_id="t1", **_NO_STORES, continuation=False, load=load, inputs=lambda: (("fp",), None)
    )

    leader_rows, follower_rows = _race(read, load)

    assert load.calls == 1
    assert follower_rows is leader_rows


def test_a_follower_builds_its_own_rows_when_the_leader_fails() -> None:
    load = _SlowLoad(fail_first=True)
    read = lambda: finding_walk_cache.reuse_rows(  # noqa: E731
        ("current_rows", None), tenant_id="t1", job_store=None, inputs=lambda: (("fp",), None), load=load
    )

    leader, follower = _race(read, load)

    assert isinstance(leader, RuntimeError)
    assert follower == [{"id": "row-2"}]
    assert load.calls == 2


def test_first_pages_without_a_fingerprint_never_share_a_build() -> None:
    load = _SlowLoad()
    read = lambda: finding_walk_cache.walk_rows(_KEY, tenant_id="t1", **_NO_STORES, continuation=False, load=load)  # noqa: E731

    leader_rows, follower_rows = _race(read, load)

    assert load.calls == 2
    assert follower_rows == [{"id": "row-2"}]
    assert leader_rows == [{"id": "row-1"}]


def test_different_tenants_never_wait_on_each_other() -> None:
    load = _SlowLoad()

    def read(tenant: str):
        return lambda: finding_walk_cache.reuse_rows(
            ("current_rows", None), tenant_id=tenant, job_store=None, inputs=lambda: (("fp",), None), load=load
        )

    leader = threading.Thread(target=read("t1"))
    leader.start()
    assert load.started.wait(10)
    began = time.perf_counter()
    other = read("t2")()
    waited = time.perf_counter() - began
    load.release.set()
    leader.join(10)

    assert other == [{"id": "row-2"}]
    assert waited < 1.0
