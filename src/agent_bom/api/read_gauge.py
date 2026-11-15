"""Let the PostgreSQL current-graph copy child yield PostgreSQL to graph and findings reads.

The copy child streams a whole source snapshot out of PostgreSQL. On a small
host the reads the API serves beside it (an explicit-scan graph page, its
incident edges and context nodes) wait inside PostgreSQL behind that stream.

The API counts its in-flight ``/v1/graph`` and ``/v1/findings`` requests and
publishes the count in an 8-byte private file it maps into memory, so an update
is a memory write, not a system call. The child maps the same file read-only;
its path travels in the child's stdin request, never in argv. Between batches
the child waits while the count is above zero, at most ``MAX_BATCH_PAUSE_SECONDS``
per batch and ``MAX_TOTAL_PAUSE_SECONDS`` per copy, so a busy API slows the
build but cannot stop it. With no reads in flight there is no pause.

The count is per API process, the same scope as the child it starts: reads in
another worker or replica are not seen. A missing or unreadable gauge reads as
zero, so the copy never waits on a broken gauge.
"""

from __future__ import annotations

import atexit
import mmap
import os
import struct
import tempfile
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from time import monotonic as _monotonic
from time import sleep as _sleep

from agent_bom.core.settings import SettingError, env_bool
from agent_bom.storage.projection_cache import cache_directory

ESTATE_READ_PREFIXES = ("/v1/graph", "/v1/findings")
MAX_BATCH_PAUSE_SECONDS = 0.5
MAX_TOTAL_PAUSE_SECONDS = 30.0
POLL_SECONDS = 0.01
_FORMAT = "<q"
_SIZE = struct.calcsize(_FORMAT)

_lock = threading.Lock()
_count = 0
_gauge: tuple[str, mmap.mmap] | None = None
# Whether the current request is counted; it follows the request into worker threads.
_counted: ContextVar[bool] = ContextVar("estate_read_counted", default=False)


def throttle_enabled() -> bool:
    """``AGENT_BOM_PG_COPY_THROTTLE=1`` turns the yield on; it is off by default.

    Measured on a 4-vCPU runner at 5,000 agents it lowered the graph median
    after a push but nearly doubled the copy (22.8 s to 41.7 s), and the first
    findings read then waited the full cold-start budget.
    """
    try:
        return env_bool("AGENT_BOM_PG_COPY_THROTTLE", False)
    except SettingError:
        return False


def counts(path: str) -> bool:
    """Whether a request path is a graph or findings read the copy yields to."""
    return any(path == prefix or path.startswith(prefix + "/") for prefix in ESTATE_READ_PREFIXES)


def _publish() -> None:
    if _gauge is not None:
        struct.pack_into(_FORMAT, _gauge[1], 0, max(_count, 0))


def enter() -> None:
    global _count
    with _lock:
        _count += 1
        _publish()


def leave() -> None:
    global _count
    with _lock:
        _count -= 1
        _publish()


@contextmanager
def counted_read() -> Iterator[None]:
    """Count this request as an estate read for its duration (the API middleware)."""
    token = _counted.set(True)
    enter()
    try:
        yield
    finally:
        if _counted.get():
            leave()
        _counted.reset(token)


@contextmanager
def waiting_on_build() -> Iterator[None]:
    """Stop counting this request while it waits on a current-graph build.

    A cold read waits for the build it triggered; still counting it would make
    the copy yield to its own waiter.
    """
    if not _counted.get():
        yield
        return
    leave()
    token = _counted.set(False)
    try:
        yield
    finally:
        _counted.reset(token)
        enter()


def gauge_path() -> str:
    """The process's gauge file, created on first use under the projection cache directory."""
    global _gauge
    with _lock:
        if _gauge is None:
            directory = cache_directory()
            directory.mkdir(parents=True, exist_ok=True)
            descriptor, path = tempfile.mkstemp(prefix=f"reads-{os.getpid()}-", suffix=".gauge", dir=directory)
            try:
                os.write(descriptor, b"\0" * _SIZE)
                _gauge = (path, mmap.mmap(descriptor, _SIZE))
            finally:
                os.close(descriptor)
            atexit.register(_remove, path)
            _publish()
        return _gauge[0]


def _remove(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass  # best effort at exit: another process or a cleanup may already have removed the gauge file


def reset_for_tests() -> None:
    global _count, _gauge
    with _lock:
        if _gauge is not None:
            _gauge[1].close()
            _remove(_gauge[0])
        _count, _gauge = 0, None


class CopyThrottle:
    """The child's side: pause between batches while the API has estate reads in flight."""

    def __init__(
        self,
        path: str | None,
        *,
        batch_cap: float = MAX_BATCH_PAUSE_SECONDS,
        total_cap: float = MAX_TOTAL_PAUSE_SECONDS,
        clock: Callable[[], float] = _monotonic,
        sleep: Callable[[float], None] = _sleep,
    ) -> None:
        self._view: mmap.mmap | None = None
        if path:
            try:
                with open(path, "rb") as handle:
                    if os.fstat(handle.fileno()).st_size >= _SIZE:
                        self._view = mmap.mmap(handle.fileno(), _SIZE, access=mmap.ACCESS_READ)
            except OSError:
                self._view = None
        self._batch_cap, self._total_cap = batch_cap, total_cap
        self._clock, self._sleep = clock, sleep
        self.paused_seconds = 0.0

    def readers(self) -> int:
        if self._view is None:
            return 0
        return max(int(struct.unpack_from(_FORMAT, self._view, 0)[0]), 0)

    def pause(self) -> float:
        """Wait while reads are in flight, within both caps; return the seconds waited."""
        allowed = min(self._batch_cap, self._total_cap - self.paused_seconds)
        if allowed <= 0 or not self.readers():
            return 0.0
        started = self._clock()
        while self.readers() and (waited := self._clock() - started) < allowed:
            self._sleep(min(POLL_SECONDS, allowed - waited))
        waited = self._clock() - started
        self.paused_seconds += waited
        return waited


__all__ = [
    "ESTATE_READ_PREFIXES",
    "MAX_BATCH_PAUSE_SECONDS",
    "MAX_TOTAL_PAUSE_SECONDS",
    "CopyThrottle",
    "counts",
    "enter",
    "gauge_path",
    "leave",
]
