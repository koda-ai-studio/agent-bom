"""Bounded background work for rebuildable current-estate projections.

Durable scan/job revisions are the work source. A lost process queue is retried
by the next read or commit warmer; it never loses a scan or promotes partial
work. Existing per-store file locks and generation receipts still own promotion.
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, wait
from typing import Any, cast

from starlette.exceptions import HTTPException

from agent_bom.api.finding_read_context import cached_read, finding_read_scope, read_once
from agent_bom.api.tenant_worker import submit_tenant_bound
from agent_bom.core.settings import env_raw

logger = logging.getLogger(__name__)
BUILDING_CODE = "current_estate_building"
ROTATING_CODE = "current_estate_generation_rotating"


def generation_rotating() -> HTTPException:
    """Evidence kept moving through the retry budget: retryable, not a conflict."""
    detail = {"code": ROTATING_CODE, "message": "The current estate is being updated; retry the read shortly."}
    return HTTPException(503, cast(str, detail), headers={"Retry-After": "1"})


def build_wait_seconds() -> float:
    """Read wait budget; background work can outlive it."""
    try:
        return max(0.0, float(env_raw("AGENT_BOM_CURRENT_GRAPH_BUILD_WAIT_MS") or 2000) / 1000)
    except ValueError:
        return 2.0


def build_refusal(*, failed: bool = False) -> HTTPException:
    detail = {
        "code": "current_estate_build_unavailable" if failed else BUILDING_CODE,
        "message": "The current graph could not be prepared; retry shortly."
        if failed
        else "The current graph is being prepared; retry shortly.",
    }
    return HTTPException(503, cast(str, detail), headers={"Retry-After": "1"})


def _build(store: Any, tenant: str, prepared: tuple[Any, ...] | None) -> str:
    with finding_read_scope():
        if prepared is not None:
            with store._building(tenant, wait=True):
                return cast(str, store._build_and_promote(tenant, *prepared))
        return cast(str, store._current_id(tenant))


def current_view_coverage(store: Any, *, tenant_id: str, scan_id: str) -> dict[str, Any]:
    coverage = store._coverage.get(scan_id, {"status": "unknown", "reason": "Collection coverage is unknown."})
    if cached_read((f"current-previous:{id(store)}", tenant_id)) == scan_id:
        return {
            **coverage,
            "refresh_status": "building",
            "freshness": "previous_generation",
            "as_of": store._generation_created_at(tenant_id, scan_id),
            "reason": "Showing the previous complete graph while the current view is prepared.",
        }
    return cast(dict[str, Any], coverage)


class CurrentBuildQueue:
    """Coalesce by backing-store wrapper and tenant; bound running and queued work.

    Per tenant at most one build runs and at most one trailing build waits: a
    commit that lands while its tenant's build already runs marks one rebuild
    for when that build ends, because the running build read older evidence.
    Any number of commits in that window collapse into the one trailing build.
    """

    def __init__(self, *, workers: int = 2, capacity: int = 64) -> None:
        self.executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="current-graph-build")
        self.capacity = capacity
        # Reentrant: a build that is already done runs its callback inline, under the caller's hold.
        self.lock = threading.RLock()
        self.pending: dict[tuple[Any, str], Future[str]] = {}
        self.trailing: set[tuple[Any, str]] = set()

    def submit(self, store: Any, tenant: str, prepared: tuple[Any, ...] | None = None, *, after_commit: bool = False) -> Future[str] | None:
        key = (store, tenant)
        with self.lock:
            if current := self.pending.get(key):
                if not current.done():
                    if after_commit and current.running():
                        self.trailing.add(key)
                    return current
                del self.pending[key]
            if len(self.pending) >= self.capacity:
                return None
            return self._start(key, prepared)

    def _start(self, key: tuple[Any, str], prepared: tuple[Any, ...] | None) -> Future[str]:
        """Start one build; callers hold ``lock``."""
        store, tenant = key
        future = submit_tenant_bound(self.executor, tenant, _build, store, tenant, prepared)
        self.pending[key] = future

        def finished(result: Future[str]) -> None:
            with self.lock:
                if self.pending.get(key) is result:
                    del self.pending[key]
                    if key in self.trailing:
                        self.trailing.discard(key)
                        try:
                            self._start(key, None)
                        except RuntimeError:  # executor shut down: the next read or commit rebuilds
                            pass
            if not result.cancelled() and (error := result.exception()) is not None and not isinstance(error, HTTPException):
                logger.warning("Current graph background build failed (%s); retry remains available", type(error).__name__)

        future.add_done_callback(finished)
        return future

    def wait_idle(self, timeout: float) -> bool:
        """Wait until no build is queued, running or trailing, at most ``timeout`` seconds; True when idle."""
        deadline = time.monotonic() + timeout
        while True:
            with self.lock:
                running = [future for future in self.pending.values() if not future.done()]
                # A finished build hands over to its trailing build in its done callback.
                handing_over = bool(self.trailing) or any(future.done() for future in self.pending.values())
            remaining = deadline - time.monotonic()
            if not running and not handing_over:
                return True
            if remaining <= 0:
                return False
            if running:
                wait(running, timeout=remaining)
            else:
                time.sleep(min(0.01, remaining))


_QUEUE = CurrentBuildQueue()


def wait_for_current_builds(timeout: float) -> bool:
    """Block until this process's queued and running current-graph builds finish (bounded)."""
    return _QUEUE.wait_idle(timeout)


def schedule_current_rebuild(store: Any, tenant_id: str) -> bool:
    """Queue the tenant's current-graph rebuild now instead of on its next read (push-commit hook).

    Never waits; a read arriving meanwhile coalesces onto this build. False when
    ``store`` keeps no current-estate projection.
    """
    if not tenant_id:
        return False
    if not callable(getattr(store, "prepare_current", None)):
        return False
    return _QUEUE.submit(store, tenant_id, after_commit=True) is not None


def await_current_build(store: Any, tenant: str, *, seconds: float, prepared: tuple[Any, ...] | None = None) -> str | None:
    """Wait only the request budget; a timeout leaves admitted work running."""
    future = _QUEUE.submit(store, tenant, prepared)
    if future is None or not wait([future], timeout=seconds).done:
        return None
    try:
        return future.result()
    except HTTPException:
        raise
    except Exception as exc:  # broad-except: expose a retryable state, never source evidence or secret-bearing exceptions
        raise build_refusal(failed=True) from exc


def resolve_request_current(store: Any, tenant: str, epoch: str, evidence: tuple[Any, ...], previous: str) -> str:
    """Reuse the request's evidence read, keeping build work outside its scope."""
    prepared = (epoch, *evidence)
    # An existing complete graph makes this a refresh, not a cold start: serve
    # it at once, labelled, while the coalesced worker builds. Only a cold start
    # waits for read-your-writes. Explicit snapshots stay exact.
    seconds = 0.0 if previous else build_wait_seconds()
    completed = await_current_build(store, tenant, seconds=seconds, prepared=prepared)
    with store._lock.shared():
        if live := store._cached_live_id(tenant, evidence[3]):
            return cast(str, store._pin(live))
    # A coalesced worker may have prepared an older evidence revision. Queue
    # this reader's revision too; do not silently present the older one as fresh.
    if completed:
        previous = previous or completed
        await_current_build(store, tenant, seconds=0, prepared=prepared)
    with store._lock.shared():
        if previous and store._live(tenant, previous) and not cached_read((f"current-count-evidence:{id(store)}", tenant)):
            read_once((f"current-previous:{id(store)}", tenant), lambda: previous)
            return cast(str, store._pin(previous))
    raise build_refusal()
