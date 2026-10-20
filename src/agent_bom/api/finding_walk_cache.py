"""Let one cursor walk over ``GET /v1/findings`` fold its scan findings once.

A merged cursor carries the position in the sorted scan-finding list, and every
continuation page rebuilt that whole list (fold every completed job, project,
filter, sort) just to index into it: O(pages x findings) for one walk. The
first page of a walk now leaves its list here and continuation pages reuse it.

Correctness bounds:

* First pages always recompute; only continuation pages read the cache, so a
  plain list view is never served stale rows.
* The key carries the tenant, every query input of the list and the job-store
  and hub evidence revisions, so a new scan, an ingest or a lifecycle write
  invalidates it. A job store without a revision token is never cached.
* Entries expire after :data:`WALK_TTL_SECONDS` and at most
  :data:`MAX_WALKS` are kept per process. Per-row projections that read other
  stores (suppressions, reachability, redaction) still run on every page.

Opt out with ``AGENT_BOM_FINDING_WALK_CACHE=0``.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from typing import Any

from agent_bom.core.settings import SettingError, env_bool

logger = logging.getLogger(__name__)

WALK_TTL_SECONDS = 120.0
MAX_WALKS = 8

_LOCK = threading.Lock()
_CACHE: OrderedDict[tuple[Any, ...], tuple[float, list[dict[str, Any]]]] = OrderedDict()


def clear() -> None:
    with _LOCK:
        _CACHE.clear()


def _enabled() -> bool:
    try:
        return env_bool("AGENT_BOM_FINDING_WALK_CACHE", True)
    except SettingError:
        return True


def _revision(tenant_id: str, hub: Any, job_store: Any) -> tuple[str, str] | None:
    job_reader = getattr(job_store, "overview_evidence_revision", None)
    if not callable(job_reader):
        return None
    hub_reader = getattr(hub, "overview_evidence_revision", None)
    return str(job_reader(tenant_id)), str(hub_reader(tenant_id)) if callable(hub_reader) else ""


def _cached(full_key: tuple[Any, ...]) -> list[dict[str, Any]] | None:
    with _LOCK:
        hit = _CACHE.get(full_key)
        if hit is None or hit[0] <= time.monotonic():
            return None
        _CACHE.move_to_end(full_key)
        return hit[1]


def _store(full_key: tuple[Any, ...], rows: list[dict[str, Any]]) -> None:
    with _LOCK:
        _CACHE[full_key] = (time.monotonic() + WALK_TTL_SECONDS, rows)
        _CACHE.move_to_end(full_key)
        while len(_CACHE) > MAX_WALKS:
            _CACHE.popitem(last=False)


def walk_rows(
    key: tuple[Any, ...],
    *,
    tenant_id: str,
    hub: Any,
    job_store: Any,
    continuation: bool,
    load: Callable[[], list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    """The walk's sorted scan-finding rows; callers must only index into or copy them."""
    if not _enabled():
        return load()
    try:
        revision = _revision(tenant_id, hub, job_store)
    except Exception:  # broad-except: optional cache-key read on any store backend; failure only disables reuse.
        logger.debug("finding walk revision unavailable; recomputing", exc_info=False)
        revision = None
    if revision is None:
        return load()
    full_key = (tenant_id, *key, revision)
    if continuation and (rows := _cached(full_key)) is not None:
        return rows
    rows = load()
    _store(full_key, rows)
    return rows


__all__ = ["MAX_WALKS", "WALK_TTL_SECONDS", "clear", "walk_rows"]
