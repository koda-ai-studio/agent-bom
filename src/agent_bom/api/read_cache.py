"""Bounded per-process response cache for expensive tenant-scoped reads.

The exec surfaces (posture counts, compliance scorecards, the fix-first graph
view) rebuild their whole body from every stored scan payload on each request.
Those bodies depend only on the tenant's evidence: scan jobs, hub-ingested
findings, suppressions and the graph snapshot. Each of those stores exposes a
cheap mutation token that writers advance in their own transaction; the route
layer folds them into one generation string (``evidence_generation`` in the
compliance route helpers) so a body is reused only while every token is
unchanged, and a bump on any of them retires the entry before the next read.

Bounds: ``READ_CACHE_MAX_ENTRIES`` least-recently-used bodies and a short TTL
that covers inputs the generation does not (runtime observations, agent
manifests). Errors are never cached, hits are deep copies, and concurrent
misses on one key run one computation. The cache is process-local; each
worker keeps its own and a worker never serves a generation it did not read
itself. Bodies that vary per principal must put the principal in ``params``.
"""

from __future__ import annotations

import copy
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Hashable
from typing import Any

from agent_bom.core.settings import env_raw

READ_CACHE_TTL_SECONDS = 60.0
READ_CACHE_MAX_ENTRIES = 64

_Key = tuple[str, str, Hashable]
_Entry = tuple[float, str, dict[str, Any]]

_LOCK = threading.Lock()
_CACHE: OrderedDict[_Key, _Entry] = OrderedDict()
_KEY_LOCKS: dict[_Key, threading.Lock] = {}


def read_cache_ttl() -> float:
    """Configured TTL; ``0`` disables the cache entirely."""
    raw = env_raw("AGENT_BOM_READ_CACHE_TTL_SECONDS")
    if raw is None:
        return READ_CACHE_TTL_SECONDS
    try:
        return max(0.0, float(raw))
    except ValueError:
        return READ_CACHE_TTL_SECONDS


def _params_token(params: Any) -> Hashable:
    if isinstance(params, dict):
        return tuple(sorted((str(key), _params_token(value)) for key, value in params.items()))
    if isinstance(params, (list, tuple)):
        return tuple(_params_token(value) for value in params)
    return params if isinstance(params, Hashable) else repr(params)


def cached_read(
    kind: str,
    tenant_id: str,
    params: Any,
    compute: Callable[[], dict[str, Any]],
    *,
    generation: str | None,
    ttl: float | None = None,
) -> dict[str, Any]:
    """Return ``compute()`` for ``(kind, tenant, params)``, reused while ``generation`` holds."""
    ttl = read_cache_ttl() if ttl is None else ttl
    if generation is None or ttl <= 0:
        return compute()
    key: _Key = (kind, tenant_id, _params_token(params))
    with _LOCK:
        key_lock = _KEY_LOCKS.setdefault(key, threading.Lock())
    try:
        with key_lock:
            hit = _get(key, generation)
            if hit is not None:
                return hit
            payload = compute()
            _put(key, generation, payload, ttl)
            return payload
    finally:
        with _LOCK:
            if len(_KEY_LOCKS) > READ_CACHE_MAX_ENTRIES and not key_lock.locked():
                _KEY_LOCKS.pop(key, None)


def _get(key: _Key, generation: str) -> dict[str, Any] | None:
    with _LOCK:
        entry = _CACHE.get(key)
        if entry is None:
            return None
        expires_at, cached_generation, payload = entry
        if cached_generation != generation or expires_at <= time.monotonic():
            del _CACHE[key]
            return None
        _CACHE.move_to_end(key)
        return copy.deepcopy(payload)


def _put(key: _Key, generation: str, payload: dict[str, Any], ttl: float) -> None:
    snapshot = copy.deepcopy(payload)
    with _LOCK:
        _CACHE[key] = (time.monotonic() + ttl, generation, snapshot)
        _CACHE.move_to_end(key)
        while len(_CACHE) > READ_CACHE_MAX_ENTRIES:
            _CACHE.popitem(last=False)


def read_cache_get(kind: str, tenant_id: str, params: Any, *, generation: str | None) -> dict[str, Any] | None:
    """Cached body for the key at ``generation``, or ``None``; for async callers that cannot hold a key lock."""
    if generation is None or read_cache_ttl() <= 0:
        return None
    return _get((kind, tenant_id, _params_token(params)), generation)


def read_cache_put(kind: str, tenant_id: str, params: Any, payload: dict[str, Any], *, generation: str | None) -> None:
    """Store a body computed at ``generation``; a no-op when the generation is unknown or caching is off."""
    ttl = read_cache_ttl()
    if generation is None or ttl <= 0:
        return
    _put((kind, tenant_id, _params_token(params)), generation, payload, ttl)


def read_cache_size() -> int:
    with _LOCK:
        return len(_CACHE)


def clear_read_cache() -> None:
    with _LOCK:
        _CACHE.clear()
        _KEY_LOCKS.clear()


__all__ = [
    "READ_CACHE_MAX_ENTRIES",
    "READ_CACHE_TTL_SECONDS",
    "cached_read",
    "clear_read_cache",
    "read_cache_get",
    "read_cache_put",
    "read_cache_size",
    "read_cache_ttl",
]
