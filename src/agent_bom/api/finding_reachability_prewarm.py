"""Build the findings reachability index right after a snapshot commits.

``GET /v1/findings?reachability=`` joins findings against the snapshot's
evidence-bearing attack paths through an index cached per snapshot generation
(:mod:`agent_bom.api.finding_reachability`). The first reader after a commit
paid the whole build. Once a snapshot commits, one background worker builds it
through the same public projection the route calls, so the cache key matches.

Bounded and best-effort, like the roll-up warm-up: one worker thread per
process, at most one pending warm-up per tenant (repeat commits coalesce),
never on the event loop, and a failure is dropped. Opt out with
``AGENT_BOM_FINDING_REACHABILITY_PREWARM=0``.
"""

from __future__ import annotations

import logging
import threading
from collections import OrderedDict
from typing import Any, Callable

from agent_bom.api.finding_reachability import project_persisted_graph_reachability
from agent_bom.api.graph_commit_hooks import register_commit_hook
from agent_bom.api.tenant_worker import tenant_bound_context
from agent_bom.core.settings import SettingError, env_bool

logger = logging.getLogger(__name__)

_MAX_PENDING_TENANTS = 64
#: A row carrying a vulnerability id is what makes the projection build the index.
_PROBE_ROW = {"vulnerability_id": "CVE-0000-0000"}

_LOCK = threading.Lock()
_PENDING: OrderedDict[str, Callable[[], Any]] = OrderedDict()
_WORKER: threading.Thread | None = None
_IDLE = threading.Event()
_IDLE.set()


def prewarm_reachability_index(store: Any, *, tenant_id: str) -> bool:
    """Build ``tenant_id``'s latest-snapshot reachability index into the cache."""
    project_persisted_graph_reachability([dict(_PROBE_ROW)], graph_store=store, tenant_id=tenant_id, scan_id=None)
    return True


def _enabled() -> bool:
    try:
        return env_bool("AGENT_BOM_FINDING_REACHABILITY_PREWARM", True)
    except SettingError:
        return True


def _next() -> tuple[str, Callable[[], Any]] | None:
    global _WORKER
    with _LOCK:
        if not _PENDING:
            _WORKER = None
            _IDLE.set()
            return None
        return _PENDING.popitem(last=False)


def _drain() -> None:
    while (item := _next()) is not None:
        tenant_id, store_factory = item
        try:
            with tenant_bound_context(tenant_id):
                prewarm_reachability_index(store_factory(), tenant_id=tenant_id)
        except Exception:  # broad-except: background worker loop; a failed warm-up leaves the first reader to build the index.
            logger.debug("finding reachability warm-up skipped", exc_info=False)


def schedule_reachability_prewarm(store_factory: Callable[[], Any], *, tenant_id: str) -> bool:
    """Queue a warm-up of ``tenant_id``'s latest snapshot; False when disabled."""
    global _WORKER
    if not _enabled():
        return False
    with _LOCK:
        _PENDING[tenant_id] = store_factory
        _PENDING.move_to_end(tenant_id)
        while len(_PENDING) > _MAX_PENDING_TENANTS:
            _PENDING.popitem(last=False)
        if _WORKER is not None and _WORKER.is_alive():
            return True
        worker = threading.Thread(target=_drain, name="finding-reachability-prewarm", daemon=True)
        try:
            worker.start()
        except RuntimeError:  # interpreter shutdown: skip the warm-up
            _PENDING.clear()
            return False
        _IDLE.clear()
        _WORKER = worker
    return True


def _on_commit(store_factory: Callable[[], Any], *, tenant_id: str) -> None:
    schedule_reachability_prewarm(store_factory, tenant_id=tenant_id)


register_commit_hook("finding_reachability_prewarm", _on_commit)


def wait_idle(timeout: float) -> bool:
    """Block until no warm-up is queued or running (tests and orderly shutdown)."""
    return _IDLE.wait(timeout)


__all__ = ["prewarm_reachability_index", "schedule_reachability_prewarm", "wait_idle"]
