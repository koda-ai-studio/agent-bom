"""Let one cursor walk over ``GET /v1/findings`` fold its scan findings once.

A merged cursor carries the position in the sorted scan-finding list, and every
continuation page rebuilt that whole list (fold every completed job, project,
filter, sort) just to index into it: O(pages x findings) for one walk. The
first page of a walk now leaves its list here and continuation pages reuse it.

Correctness bounds:

* A first page reads the cache only when its caller supplies ``inputs``: a
  fingerprint of every other input the rows were built from and the wall-clock
  instant the clock alone would change them (see
  :mod:`agent_bom.api.finding_row_inputs`). Without one it recomputes, so a
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
MAX_CACHED_ROWS = 200_000

_LOCK = threading.Lock()
# key -> (monotonic expiry, wall-clock horizon or None, rows)
_CACHE: OrderedDict[tuple[Any, ...], tuple[float, float | None, list[dict[str, Any]]]] = OrderedDict()
RowInputs = Callable[[], tuple[tuple[Any, ...], float | None]]


def _wall_clock() -> float:
    return time.time()


def _held_rows() -> int:
    # A first page and its walk share one row list; count it once.
    return sum(len(rows) for rows in {id(entry[2]): entry[2] for entry in _CACHE.values()}.values())


def cached_row_count() -> int:
    with _LOCK:
        return _held_rows()


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
        if hit is None or hit[0] <= time.monotonic() or (hit[1] is not None and hit[1] <= _wall_clock()):
            return None
        _CACHE.move_to_end(full_key)
        return hit[2]


def _store(full_key: tuple[Any, ...], rows: list[dict[str, Any]], horizon: float | None = None) -> None:
    if len(rows) > MAX_CACHED_ROWS:
        return
    with _LOCK:
        _CACHE[full_key] = (time.monotonic() + WALK_TTL_SECONDS, horizon, rows)
        _CACHE.move_to_end(full_key)
        while len(_CACHE) > MAX_WALKS or _held_rows() > MAX_CACHED_ROWS:
            _CACHE.popitem(last=False)


def walk_rows(
    key: tuple[Any, ...],
    *,
    tenant_id: str,
    hub: Any,
    job_store: Any,
    continuation: bool,
    load: Callable[[], list[dict[str, Any]]],
    inputs: RowInputs | None = None,
) -> list[dict[str, Any]]:
    """The walk's sorted scan-finding rows; callers must only index into or copy them."""
    if not _enabled():
        return load()
    fingerprint: tuple[tuple[Any, ...], float | None] | None = None
    try:
        revision = _revision(tenant_id, hub, job_store)
        if revision is not None and inputs is not None and not continuation:
            fingerprint = inputs()
    except Exception:  # broad-except: optional cache-key read on any store backend; failure only disables reuse.
        logger.debug("finding walk revision unavailable; recomputing", exc_info=False)
        revision = None
    if revision is None:
        return load()
    full_key = (tenant_id, *key, revision)
    if continuation and (rows := _cached(full_key)) is not None:
        return rows
    first_key = (*full_key, fingerprint[0]) if fingerprint is not None else None
    if first_key is not None and (rows := _cached(first_key)) is not None:
        return rows
    rows = load()
    _store(full_key, rows)
    if first_key is not None and fingerprint is not None:
        _store(first_key, rows, fingerprint[1])
    return rows


__all__ = ["MAX_CACHED_ROWS", "MAX_WALKS", "WALK_TTL_SECONDS", "RowInputs", "cached_row_count", "clear", "walk_rows"]
