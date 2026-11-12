"""Prepare recent tenants' current graphs at API start-up, before the first read asks.

A new process holds no current-estate generation in memory, so its first graph
read built one and, past ``AGENT_BOM_CURRENT_GRAPH_BUILD_WAIT_MS``, answered
503 ``current_estate_building``. At start-up one daemon thread now prepares the
tenants with the newest completed scans through the same coalescing build queue
reads use, so a read that arrives mid warm-up joins that build instead of
starting another, and still gets its bounded wait and ``Retry-After``.

Bounded and best-effort: tenants come from the newest ``MAX_JOBS_SCANNED``
completed jobs, at most ``MAX_TENANTS``, newest first; each waits at most
``per_tenant_seconds``; the run never raises and reports what it skipped.
Disable with ``AGENT_BOM_CURRENT_GRAPH_PREWARM=0``.

While it runs, ``/readyz`` reports ``current_graph_prewarming`` so an
orchestrator routes no traffic to a cold replica, for at most
``AGENT_BOM_CURRENT_GRAPH_PREWARM_READY_SECONDS`` (default 120). Liveness never
waits on it.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from typing import Any, cast

from agent_bom.api import stores
from agent_bom.api.models import JobStatus
from agent_bom.api.tenant_worker import run_tenant_bound
from agent_bom.core.settings import SettingError, env_bool, env_raw

logger = logging.getLogger(__name__)

MAX_JOBS_SCANNED = 1000
MAX_TENANTS = 16
DEFAULT_PER_TENANT_SECONDS = 300.0
DEFAULT_READY_SECONDS = 120.0

_LAST_RUN: dict[str, Any] = {"status": "not_started"}
_STARTED_AT: list[float] = []


def _enabled() -> bool:
    try:
        return env_bool("AGENT_BOM_CURRENT_GRAPH_PREWARM", True)
    except SettingError:
        return True


def _per_tenant_seconds() -> float:
    try:
        return max(1.0, float(env_raw("AGENT_BOM_CURRENT_GRAPH_PREWARM_TENANT_SECONDS") or DEFAULT_PER_TENANT_SECONDS))
    except ValueError:
        return DEFAULT_PER_TENANT_SECONDS


def _ready_seconds() -> float:
    try:
        return max(0.0, float(env_raw("AGENT_BOM_CURRENT_GRAPH_PREWARM_READY_SECONDS") or DEFAULT_READY_SECONDS))
    except ValueError:
        return DEFAULT_READY_SECONDS


def startup_prewarm_holding_readiness() -> bool:
    """Whether readiness should wait: the start-up warm-up runs and is inside its readiness bound."""
    if _LAST_RUN.get("status") != "running" or not _STARTED_AT:
        return False
    return time.monotonic() - _STARTED_AT[-1] < _ready_seconds()


def _recent_tenants(job_store: Any) -> tuple[list[str], int]:
    rows = job_store.list_summary(all_tenants=True, status=JobStatus.DONE, limit=MAX_JOBS_SCANNED)
    ordered = list(dict.fromkeys(str(row["tenant_id"]) for row in rows if row.get("tenant_id")))
    return ordered[:MAX_TENANTS], max(0, len(ordered) - MAX_TENANTS)


def prewarm_current_graphs(graph_store: Any, job_store: Any, *, per_tenant_seconds: float) -> dict[str, Any]:
    """Prepare the newest tenants' current graphs; never raises, never touches the graph store without scans."""
    try:
        tenants, skipped = _recent_tenants(job_store)
    except Exception as exc:  # broad-except: start-up warm-up boundary; reads still build on demand.
        logger.warning("Current graph prewarm could not list tenants (%s)", type(exc).__name__)
        return {"status": "incomplete", "reason": "job_store_unavailable", "tenants_prepared": 0, "tenants_skipped": 0, "tenants_failed": 0}
    prepared = failed = 0
    prepare: Callable[..., bool] | None = getattr(graph_store, "prepare_current", None) if tenants else None
    if prepare is None:
        tenants = []
    for tenant in tenants:
        try:
            if run_tenant_bound(tenant, cast(Callable[..., bool], prepare), tenant, seconds=per_tenant_seconds):
                prepared += 1
            else:
                failed += 1
        except Exception as exc:  # broad-except: one tenant's failure must not stop the others; never log evidence.
            failed += 1
            logger.warning("Current graph prewarm failed for one tenant (%s); its first read builds on demand", type(exc).__name__)
    summary: dict[str, Any] = {
        "status": "complete" if not (failed or skipped) else "incomplete",
        "tenants_prepared": prepared,
        "tenants_skipped": skipped,
        "tenants_failed": failed,
    }
    if skipped:
        summary["reason"] = "tenant_cap"
    return summary


def last_run() -> dict[str, Any]:
    """Tenant-free summary of this process's start-up warm-up."""
    return dict(_LAST_RUN)


def _run() -> None:
    job_store = stores._get_store()

    class _LazyGraphStore:
        """Resolve the configured graph store only when a tenant needs it."""

        def __getattr__(self, name: str) -> Any:
            return getattr(stores._get_graph_store(), name)

    summary = prewarm_current_graphs(_LazyGraphStore(), job_store, per_tenant_seconds=_per_tenant_seconds())
    _LAST_RUN.clear()
    _LAST_RUN.update(summary)
    logger.info(
        "Current graph prewarm %s: %d tenant(s) prepared, %d skipped, %d failed",
        summary["status"],
        summary["tenants_prepared"],
        summary["tenants_skipped"],
        summary["tenants_failed"],
    )


def start_current_graph_prewarm() -> threading.Thread | None:
    """Start the warm-up on a daemon thread; None when disabled or a thread cannot start."""
    if not _enabled():
        _LAST_RUN.clear()
        _LAST_RUN.update(status="disabled")
        return None
    thread = threading.Thread(target=_run, name="current-graph-prewarm", daemon=True)
    # Marked running before the thread starts so no probe sees a ready gap.
    _STARTED_AT[:] = [time.monotonic()]
    _LAST_RUN.clear()
    _LAST_RUN.update(status="running")
    try:
        thread.start()
    except RuntimeError:
        _LAST_RUN.clear()
        _LAST_RUN.update(status="incomplete", reason="thread_unavailable")
        return None
    return thread


__all__ = ["last_run", "prewarm_current_graphs", "start_current_graph_prewarm", "startup_prewarm_holding_readiness"]
