"""Warm the roll-up views the graph page opens first, right after a snapshot commits.

A cold roll-up at 115k nodes cost 2.8 s (attack-path mode 4.6 s, the
auto-descended drill 4.0 s) against ~50 ms warm. The first reader of every new
snapshot paid that. Once a snapshot commits, one background worker computes
those first views into :mod:`agent_bom.api.graph_rollup_cache` under the same
generation-scoped keys the route reads, so the first reader is served warm.

Bounded and best-effort: one worker thread per process, at most one pending
warm-up per tenant (repeat commits coalesce), never on the event loop, and a
failure is logged and dropped — it can never fail or slow the snapshot write.
The cache is per process: a request served by another API worker process
still computes its own first view.
"""

from __future__ import annotations

import logging
import threading
from collections import OrderedDict
from typing import Any, Callable, Literal

from agent_bom.api import graph_rollup_cache
from agent_bom.api.finding_suppression import suppression_revision
from agent_bom.api.graph_commit_hooks import register_commit_hook
from agent_bom.api.graph_generation import optional_generation, snapshot_fingerprint
from agent_bom.api.graph_store import containment_drilldown_graph
from agent_bom.api.scan_finding_read import suppressed_finding_ids
from agent_bom.api.tenant_worker import tenant_bound_context
from agent_bom.core.settings import SettingError, env_bool
from agent_bom.graph.rollup import ROLLUP_RELATIONSHIPS
from agent_bom.graph.view_payloads import _graph_rollup_payload

logger = logging.getLogger(__name__)

#: Retention for warmed entries. Keys are generation-scoped, so a replaced
#: snapshot can never be answered from them; the window only bounds memory.
PREWARM_TTL_SECONDS = 900
#: Top-level page sizes warmed: the graph page's request, then the API default.
FIRST_VIEW_LIMITS: tuple[int, ...] = (100, 200)
#: The graph page descends through single-container levels on its own.
AUTO_DESCEND_DEPTH = 3
_DRILL_LIMIT = 100
_MAX_PENDING_TENANTS = 64

_LOCK = threading.Lock()
_PENDING: OrderedDict[str, Callable[[], Any]] = OrderedDict()
_WORKER: threading.Thread | None = None
_IDLE = threading.Event()
_IDLE.set()


def rollup_cache_key(
    store: Any,
    tenant: str,
    identity: tuple[str, str],
    *,
    node: str | None = None,
    min_severity: str | None = None,
    exposed: bool = False,
    toxic: bool = False,
    mode: str = "rollup",
    offset: int = 0,
    limit: int = 0,
    suppressions: str = "",
) -> tuple[Any, ...]:
    """The roll-up cache key, shared by the route and the warm-up.

    The payload depends on the tenant, the snapshot generation and the view
    parameters only — never on which principal asked — so the key carries no
    principal; keying by API key made every caller pay the cold read again.
    ``suppressions`` is the tenant's suppression revision: an approval or
    revoke changes the counts without a new snapshot.
    """
    paged = mode == "rollup" or bool(node)
    # The route's store is a per-request current-estate wrapper; its backing
    # store is the stable identity (a wrapper's id is reused only by accident).
    return (
        id(getattr(store, "_graph_store", store)),
        tenant,
        tuple(identity),
        node,
        min_severity,
        exposed,
        toxic,
        mode,
        offset if paged else 0,
        limit if paged else 0,
        suppressions,
    )


def load_rollup_source(store: Any, *, tenant_id: str, scan_id: str, node: str | None, mode: str) -> Any:
    """The graph one roll-up view is computed from: a drill subtree, the roll-up projection, or the full load."""
    if node:
        return containment_drilldown_graph(store, node_id=node, scan_id=scan_id, tenant_id=tenant_id)
    rollup_loader = getattr(store, "load_rollup_graph", None)
    if mode == "rollup" and callable(rollup_loader):
        return rollup_loader(scan_id=scan_id, tenant_id=tenant_id)
    load_kwargs: dict[str, Any] = {"scan_id": scan_id, "tenant_id": tenant_id}
    if mode != "attack_path":
        load_kwargs["relationship_types"] = ROLLUP_RELATIONSHIPS
    return store.load_graph(**load_kwargs)


def prewarm_rollup(store: Any, *, tenant_id: str) -> int:
    """Compute the latest snapshot's first roll-up views into the cache; return how many were warmed."""
    identity = optional_generation(store, tenant=tenant_id, scan_id="", generation=None, offset=0)
    key_identity = identity or snapshot_fingerprint(store, tenant=tenant_id, scan_id="")
    if not key_identity or not key_identity[1]:
        return 0
    scan_id = key_identity[0]
    warmed = 0
    suppressions = suppression_revision(tenant_id)
    suppressed = suppressed_finding_ids(tenant_id)

    def view(graph: Any, *, node: str | None = None, mode: Literal["rollup", "attack_path"] = "rollup", limit: int) -> dict[str, Any]:
        nonlocal warmed
        payload = _graph_rollup_payload(
            graph,
            node=node,
            min_severity="",
            exposed=False,
            toxic=False,
            mode=mode,
            offset=0,
            limit=limit,
            graph_store=store,
            suppressed_finding_ids=suppressed,
        )
        if identity is not None:
            payload["snapshot_generation"] = identity[1]
        key = rollup_cache_key(store, tenant_id, key_identity, node=node, mode=mode, limit=limit, suppressions=suppressions)
        graph_rollup_cache.put(key, payload, ttl=PREWARM_TTL_SECONDS)
        warmed += 1
        return payload

    graph = load_rollup_source(store, tenant_id=tenant_id, scan_id=scan_id, node=None, mode="rollup")
    first = [view(graph, limit=limit) for limit in FIRST_VIEW_LIMITS][0]
    del graph

    items = first.get("top_level") or []
    for _level in range(AUTO_DESCEND_DEPTH):
        if len(items) != 1 or not items[0].get("is_container") or not items[0].get("has_children"):
            break
        node = str(items[0]["id"])
        subtree = load_rollup_source(store, tenant_id=tenant_id, scan_id=scan_id, node=node, mode="rollup")
        items = view(subtree, node=node, limit=_DRILL_LIMIT).get("children") or []

    full = load_rollup_source(store, tenant_id=tenant_id, scan_id=scan_id, node=None, mode="attack_path")
    view(full, mode="attack_path", limit=0)
    return warmed


def _enabled() -> bool:
    try:
        return env_bool("AGENT_BOM_GRAPH_ROLLUP_PREWARM", True)
    except SettingError:
        return True


def _drain() -> None:
    global _WORKER
    while True:
        with _LOCK:
            if not _PENDING:
                _WORKER = None
                _IDLE.set()
                return
            tenant_id, store_factory = _PENDING.popitem(last=False)
        try:
            with tenant_bound_context(tenant_id):
                prewarm_rollup(store_factory(), tenant_id=tenant_id)
        except Exception:  # noqa: BLE001 - a warm-up is an optimisation; the next reader computes cold
            logger.debug("graph rollup warm-up skipped", exc_info=False)


def schedule_rollup_prewarm(store_factory: Callable[[], Any], *, tenant_id: str) -> None:
    """Queue a warm-up of ``tenant_id``'s latest snapshot and return immediately."""
    global _WORKER
    if not _enabled():
        return
    with _LOCK:
        _PENDING[tenant_id] = store_factory
        _PENDING.move_to_end(tenant_id)
        while len(_PENDING) > _MAX_PENDING_TENANTS:
            _PENDING.popitem(last=False)
        if _WORKER is not None and _WORKER.is_alive():
            return
        worker = threading.Thread(target=_drain, name="graph-rollup-prewarm", daemon=True)
        try:
            worker.start()
        except RuntimeError:  # the interpreter cannot start a thread (shutdown): skip the warm-up
            _PENDING.clear()
            return
        _IDLE.clear()
        _WORKER = worker


def _on_commit(store_factory: Callable[[], Any], *, tenant_id: str) -> None:
    schedule_rollup_prewarm(store_factory, tenant_id=tenant_id)


register_commit_hook("graph_rollup_prewarm", _on_commit)


def wait_idle(timeout: float) -> bool:
    """Block until no warm-up is queued or running (tests and orderly shutdown)."""
    return _IDLE.wait(timeout)


__all__ = [
    "AUTO_DESCEND_DEPTH",
    "FIRST_VIEW_LIMITS",
    "PREWARM_TTL_SECONDS",
    "load_rollup_source",
    "prewarm_rollup",
    "rollup_cache_key",
    "schedule_rollup_prewarm",
    "wait_idle",
]
