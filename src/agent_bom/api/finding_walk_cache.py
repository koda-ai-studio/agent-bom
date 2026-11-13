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
* Readers that miss the same key at once build it once: an ingest commit
  bumps the revision under every reader in flight, and each rebuilding the
  same fold beside the others made all of them wait for all of them. Only
  keys the cache may serve are shared, so a first page without ``inputs``
  still builds its own rows.

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
MAX_WALKS = 16
MAX_CACHED_ROWS = 200_000
# A reader waits this long for another reader's build of the same key, then builds its own.
FLIGHT_WAIT_SECONDS = 30.0

_LOCK = threading.Lock()
# key -> (monotonic expiry, wall-clock horizon or None, rows)
_CACHE: OrderedDict[tuple[Any, ...], tuple[float, float | None, list[dict[str, Any]]]] = OrderedDict()
RowInputs = Callable[[], tuple[tuple[Any, ...], float | None] | None]


class _Flight:
    __slots__ = ("done", "rows")

    def __init__(self) -> None:
        self.done = threading.Event()
        self.rows: list[dict[str, Any]] | None = None


_FLIGHTS: dict[tuple[Any, ...], _Flight] = {}


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


def _build_once(
    key: tuple[Any, ...], load: Callable[[], list[dict[str, Any]]], publish: Callable[[list[dict[str, Any]]], None]
) -> list[dict[str, Any]]:
    """Run ``load`` once for concurrent callers of ``key``; the builder publishes before followers wake."""
    with _LOCK:
        flight = _FLIGHTS.get(key)
        building = flight is None
        if flight is None:
            flight = _FLIGHTS[key] = _Flight()
    if not building:
        if flight.done.wait(FLIGHT_WAIT_SECONDS) and flight.rows is not None:
            return flight.rows
        return load()
    try:
        rows = load()
        publish(rows)
        flight.rows = rows
        return rows
    finally:
        with _LOCK:
            _FLIGHTS.pop(key, None)
        flight.done.set()


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

    def publish(rows: list[dict[str, Any]]) -> None:
        _store(full_key, rows)
        if first_key is not None and fingerprint is not None:
            _store(first_key, rows, fingerprint[1])

    shared_key = first_key if first_key is not None else full_key if continuation else None
    if shared_key is None:
        rows = load()
        publish(rows)
        return rows
    return _build_once(shared_key, load, publish)


def reuse_rows(
    key: tuple[Any, ...],
    *,
    tenant_id: str,
    job_store: Any,
    inputs: RowInputs,
    load: Callable[[], list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Rows ``load`` builds, reused across reads while the job revision and ``inputs`` match.

    For row sets that any first page may read (the folded scan rows); callers
    must only index into or copy them.
    """
    if not _enabled():
        return load()
    try:
        revision = _revision(tenant_id, None, job_store)
        fingerprint = inputs() if revision is not None else None
    except Exception:  # broad-except: optional cache-key read on any store backend; failure only disables reuse.
        logger.debug("finding row inputs unavailable; recomputing", exc_info=False)
        fingerprint = None
    if fingerprint is None:
        return load()
    full_key = (tenant_id, *key, revision, fingerprint[0])
    if (rows := _cached(full_key)) is not None:
        return rows
    horizon = fingerprint[1]
    return _build_once(full_key, load, lambda rows: _store(full_key, rows, horizon))


__all__ = ["MAX_CACHED_ROWS", "MAX_WALKS", "WALK_TTL_SECONDS", "RowInputs", "cached_row_count", "clear", "reuse_rows", "walk_rows"]
