"""Bounded background work for rebuildable current-estate projections.

Durable scan/job revisions are the work source. A lost process queue is retried
by the next read or commit warmer; it never loses a scan or promotes partial
work. Existing per-store file locks and generation receipts still own promotion.
"""

from __future__ import annotations

import logging
import threading
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
            "reason": "Showing the previous complete graph while the current view is prepared.",
        }
    return cast(dict[str, Any], coverage)


class CurrentBuildQueue:
    """Coalesce by backing-store wrapper and tenant; bound running and queued work."""

    def __init__(self, *, workers: int = 2, capacity: int = 64) -> None:
        self.executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="current-graph-build")
        self.capacity = capacity
        self.lock = threading.Lock()
        self.pending: dict[tuple[Any, str], Future[str]] = {}

    def submit(self, store: Any, tenant: str, prepared: tuple[Any, ...] | None = None) -> Future[str] | None:
        key = (store, tenant)
        with self.lock:
            if current := self.pending.get(key):
                if not current.done():
                    return current
                del self.pending[key]
            if len(self.pending) >= self.capacity:
                return None
            future = submit_tenant_bound(self.executor, tenant, _build, store, tenant, prepared)
            self.pending[key] = future

        def finished(result: Future[str]) -> None:
            with self.lock:
                if self.pending.get(key) is result:
                    del self.pending[key]
            if not result.cancelled() and (error := result.exception()) is not None and not isinstance(error, HTTPException):
                logger.warning("Current graph background build failed (%s); retry remains available", type(error).__name__)

        future.add_done_callback(finished)
        return future


_QUEUE = CurrentBuildQueue()


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
    completed = await_current_build(store, tenant, seconds=build_wait_seconds(), prepared=prepared)
    with store._lock.shared():
        if live := store._cached_live_id(tenant, evidence[3]):
            return cast(str, store._pin(live))
    # A coalesced worker may have prepared an older evidence revision. Queue
    # this reader's revision too; do not silently present the older one as fresh.
    if completed:
        previous = completed
        await_current_build(store, tenant, seconds=0, prepared=prepared)
    with store._lock.shared():
        if previous and store._live(tenant, previous) and not cached_read((f"current-count-evidence:{id(store)}", tenant)):
            read_once((f"current-previous:{id(store)}", tenant), lambda: previous)
            return cast(str, store._pin(previous))
    raise build_refusal()
