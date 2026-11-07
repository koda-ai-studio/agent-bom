"""A projection in use by a live holder, in any process, is never swept; an abandoned one still is.

Standalone by design: CI runs this file on every OS with ``--noconftest``, so it
needs nothing but the lease module and a temporary directory.
"""

from __future__ import annotations

import errno
import importlib.util
import os
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from agent_bom.core import file_lock
from agent_bom.storage import projection_cache

NOW = 1_800_000_000.0
DAY = 86_400.0
POSIX_ONLY = pytest.mark.skipif(os.name == "nt", reason="uses /dev/fd")
SRC = str(Path(projection_cache.__file__).resolve().parents[2])
HOLDER = """
import sys
from pathlib import Path
from agent_bom.storage import projection_cache
release = projection_cache.acquire_projection_lease(Path(sys.argv[1]))
print("held", flush=True)
sys.stdin.read()
release()
"""


def _aged(path: Path, *, age_days: float = 30) -> Path:
    path.write_bytes(b"x" * 16)
    stamp = NOW - age_days * DAY
    os.utime(path, (stamp, stamp))
    return path


def _sweep(directory: Path, **overrides) -> list[Path]:
    options = {"active": None, "keep_latest": 0, "max_age_days": 14, "now": NOW}
    options.update(overrides)
    return projection_cache.sweep_projection_cache(directory, **options)


@contextmanager
def _holder_process(path: Path) -> Iterator[subprocess.Popen[str]]:
    process = subprocess.Popen(
        [sys.executable, "-c", HOLDER, str(path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        env={**os.environ, "PYTHONPATH": SRC},
    )
    try:
        assert process.stdout is not None
        assert process.stdout.readline().strip() == "held"
        yield process
    finally:
        process.kill()
        process.communicate(timeout=30)


def _sweep_until_removed(directory: Path, path: Path, seconds: float = 10) -> list[Path]:
    # Windows documents a resource-dependent delay before a dead process's locks clear.
    deadline = time.monotonic() + seconds
    while True:
        removed = _sweep(directory)
        if path in removed or time.monotonic() >= deadline:
            return removed
        time.sleep(0.05)


def test_held_file_survives_count_and_age_limits_and_dry_run_says_so(tmp_path):
    live = _aged(tmp_path / "live.db")
    release = projection_cache.acquire_projection_lease(live)
    try:
        assert _sweep(tmp_path, dry_run=True) == []
        assert _sweep(tmp_path) == []
        assert live.exists() and projection_cache.lease_path(live).exists()
    finally:
        release()


def test_released_file_is_swept_with_every_companion(tmp_path):
    stale = _aged(tmp_path / "stale.db")
    release = projection_cache.acquire_projection_lease(stale)
    companions = [
        tmp_path / "stale.db-wal",
        tmp_path / "stale.db-shm",
        tmp_path / "stale.db.0123456789abcdef.lock",
        tmp_path / "stale.db.0123456789abcdef.epoch",
    ]
    for companion in companions:
        companion.write_bytes(b"c")
    unrelated = tmp_path / "other.db.keep"
    unrelated.write_bytes(b"u")
    release()

    assert _sweep(tmp_path) == [stale]

    assert not stale.exists()
    assert not projection_cache.lease_path(stale).exists()
    assert not any(companion.exists() for companion in companions)
    assert unrelated.exists()


def test_a_file_nobody_ever_leased_is_swept_and_a_preview_leaves_no_trace(tmp_path):
    stale = _aged(tmp_path / "stale.db")

    assert _sweep(tmp_path, dry_run=True) == [stale]
    assert stale.exists()
    assert not projection_cache.lease_path(stale).exists()

    assert _sweep(tmp_path) == [stale]
    assert not stale.exists()
    assert sorted(tmp_path.iterdir()) == []


def test_preview_keeps_an_existing_marker_on_a_file_it_only_inspected(tmp_path):
    stale = _aged(tmp_path / "stale.db")
    projection_cache.acquire_projection_lease(stale)()

    assert _sweep(tmp_path, dry_run=True) == [stale]

    assert stale.exists() and projection_cache.lease_path(stale).exists()


def test_every_holder_must_release_before_the_file_can_go(tmp_path):
    stale = _aged(tmp_path / "shared.db")
    first = projection_cache.acquire_projection_lease(stale)
    second = projection_cache.acquire_projection_lease(stale)
    assert _sweep(tmp_path) == []
    first()
    assert _sweep(tmp_path) == []
    second()
    assert _sweep(tmp_path) == [stale]


def test_release_is_safe_to_repeat(tmp_path):
    stale = _aged(tmp_path / "twice.db")
    release = projection_cache.acquire_projection_lease(stale)
    other = projection_cache.acquire_projection_lease(stale)
    release()
    release()
    assert _sweep(tmp_path) == [], "a repeated release must not drop another holder's lock"
    other()


def test_a_second_process_holding_the_lease_blocks_the_sweep(tmp_path):
    live = _aged(tmp_path / "remote.db")
    with _holder_process(live) as holder:
        assert _sweep(tmp_path, dry_run=True) == []
        assert _sweep(tmp_path) == []
        assert live.exists()
        assert holder.poll() is None


def test_a_killed_process_no_longer_blocks_the_sweep(tmp_path):
    stale = _aged(tmp_path / "crashed.db")
    with _holder_process(stale) as holder:
        assert _sweep(tmp_path) == []
        holder.kill()
        holder.wait(timeout=30)
        assert _sweep_until_removed(tmp_path, stale) == [stale]
    assert not stale.exists()
    assert not projection_cache.lease_path(stale).exists()


@pytest.mark.parametrize("code", [errno.ENOLCK, errno.EIO])
def test_sweep_deletes_nothing_when_it_cannot_take_the_lock(tmp_path, monkeypatch, code):
    stale = _aged(tmp_path / "stale.db")

    def refuse(fd: int) -> bool:
        raise OSError(code, "no locks here")

    monkeypatch.setattr(projection_cache, "try_exclusive_lock", refuse)

    assert _sweep(tmp_path, dry_run=True) == []
    assert _sweep(tmp_path) == []
    assert stale.exists()


def test_store_without_lock_support_gets_a_noop_lease_and_the_sweep_stays_away(tmp_path, monkeypatch):
    path = tmp_path / "nfs.db"

    def refuse(fd: int) -> bool:
        raise OSError(errno.ENOLCK, "no locks here")

    monkeypatch.setattr(projection_cache, "try_shared_lock", refuse)
    monkeypatch.setattr(projection_cache, "try_exclusive_lock", refuse)

    opened = projection_cache.acquire_projection_lease(path)

    opened()
    _aged(path)
    assert _sweep(tmp_path) == []
    assert path.exists()


def test_other_lock_failures_are_not_mistaken_for_lock_support_missing(tmp_path, monkeypatch):
    def refuse(fd: int) -> bool:
        raise OSError(errno.EIO, "disk trouble")

    monkeypatch.setattr(projection_cache, "try_shared_lock", refuse)

    with pytest.raises(OSError, match="disk trouble"):
        projection_cache.acquire_projection_lease(tmp_path / "bad.db")


def test_a_lease_never_outwaits_a_stuck_sweeper(tmp_path):
    path = tmp_path / "busy.db"
    marker = projection_cache.lease_path(path)
    fd = os.open(marker, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        assert file_lock.try_exclusive_lock(fd)
        with pytest.raises(TimeoutError):
            projection_cache.acquire_projection_lease(path, wait_seconds=0.1)
    finally:
        os.close(fd)


@pytest.mark.skipif(os.name == "nt", reason="an open file cannot be unlinked on Windows, so no orphaned marker can exist")
def test_a_waiter_on_a_marker_the_sweep_unlinked_moves_to_a_new_one(tmp_path):
    path = tmp_path / "raced.db"
    marker = projection_cache.lease_path(path)
    acquired: list = []
    waiter = threading.Thread(target=lambda: acquired.append(projection_cache.acquire_projection_lease(path)))
    fd = os.open(marker, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        assert file_lock.try_exclusive_lock(fd)
        waiter.start()
        time.sleep(0.05)
        marker.unlink()
    finally:
        os.close(fd)
    waiter.join(timeout=10)
    assert acquired, "the waiter never got a lease"

    assert marker.exists(), "the waiter must lock the marker on disk, not the unlinked one"
    _aged(path)
    assert _sweep(tmp_path) == []
    acquired[0]()
    assert _sweep(tmp_path) == [path]


def test_marker_without_a_projection_is_cleaned_unless_someone_holds_it(tmp_path):
    orphan = projection_cache.lease_path(tmp_path / "gone.db")
    orphan.write_bytes(b"")
    pending = tmp_path / "pending.db"
    release = projection_cache.acquire_projection_lease(pending)
    try:
        assert _sweep(tmp_path) == []
        assert not orphan.exists()
        assert projection_cache.lease_path(pending).exists()
    finally:
        release()


def test_preview_leaves_a_marker_without_a_projection_alone(tmp_path):
    orphan = projection_cache.lease_path(tmp_path / "gone.db")
    orphan.write_bytes(b"")

    assert _sweep(tmp_path, dry_run=True) == []

    assert orphan.exists()


@POSIX_ONLY
def test_leases_do_not_leak_descriptors(tmp_path):
    path = tmp_path / "churn.db"
    baseline = len(os.listdir("/dev/fd"))
    for _ in range(300):
        projection_cache.acquire_projection_lease(path)()
    assert len(os.listdir("/dev/fd")) <= baseline + 1


def test_sweeps_do_not_leak_descriptors_when_files_are_held(tmp_path):
    live = _aged(tmp_path / "held.db")
    release = projection_cache.acquire_projection_lease(live)
    try:
        if os.name == "nt":
            assert all(_sweep(tmp_path) == [] for _ in range(300))
            return
        baseline = len(os.listdir("/dev/fd"))
        for _ in range(300):
            assert _sweep(tmp_path) == []
        assert len(os.listdir("/dev/fd")) <= baseline + 1
    finally:
        release()


class _FakeMsvcrt:
    """Byte-range locks with Windows' per-handle rule: a second handle is refused even in-process."""

    LK_NBLCK = 2
    LK_UNLCK = 0

    def __init__(self) -> None:
        self.held: dict[int, set[int]] = {}

    def locking(self, fd: int, mode: int, nbytes: int) -> None:
        start = os.lseek(fd, 0, os.SEEK_CUR)
        wanted = set(range(start, start + nbytes))
        if mode == self.LK_UNLCK:
            self.held[fd] -= wanted
            return
        if any(wanted & regions for owner, regions in self.held.items() if owner != fd):
            raise OSError(errno.EACCES, "locked")
        self.held.setdefault(fd, set()).update(wanted)


@pytest.fixture
def windows_locks():
    """The Windows branch of the lock module, driven by byte-range rules matching ``LockFile``."""
    spec = importlib.util.spec_from_file_location("file_lock_windows_branch", file_lock.__file__)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    with pytest.MonkeyPatch.context() as patch:
        patch.setitem(sys.modules, "msvcrt", _FakeMsvcrt())
        patch.setattr(os, "name", "nt")
        spec.loader.exec_module(module)
    return module


@pytest.mark.skipif(os.name == "nt", reason="the real thing runs on Windows")
def test_windows_shared_holders_coexist_and_exclude_the_sweep(tmp_path, windows_locks):
    still_open: set[int] = set()

    def handle() -> int:
        fd = os.open(tmp_path / "marker", os.O_CREAT | os.O_RDWR, 0o600)
        still_open.add(fd)
        return fd

    def release(fd: int, *, exclusive: bool) -> None:
        still_open.discard(fd)
        windows_locks.release_lock(fd, exclusive=exclusive)

    try:
        first, second, sweeper = handle(), handle(), handle()
        assert windows_locks.try_shared_lock(first)
        assert windows_locks.try_shared_lock(second)
        assert not windows_locks.try_exclusive_lock(sweeper)
        release(first, exclusive=False)
        assert not windows_locks.try_exclusive_lock(sweeper)
        release(second, exclusive=False)
        assert windows_locks.try_exclusive_lock(sweeper)

        third = handle()
        assert not windows_locks.try_shared_lock(third), "a sweeping marker admits no new holder"
        release(sweeper, exclusive=True)
        assert windows_locks.try_shared_lock(third)
        release(third, exclusive=False)
    finally:
        for fd in still_open:
            os.close(fd)


@pytest.mark.skipif(os.name == "nt", reason="the real thing runs on Windows")
def test_windows_full_slot_table_refuses_instead_of_overrunning_the_sweep_range(tmp_path, windows_locks):
    handles: list[int] = []
    try:
        for _ in range(windows_locks.SHARED_SLOTS + 1):
            handles.append(os.open(tmp_path / "marker", os.O_CREAT | os.O_RDWR, 0o600))
        assert all(windows_locks.try_shared_lock(fd) for fd in handles[:-1])
        assert not windows_locks.try_shared_lock(handles[-1])
    finally:
        for fd in handles:
            os.close(fd)
