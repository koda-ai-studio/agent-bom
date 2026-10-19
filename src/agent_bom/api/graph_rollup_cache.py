"""Bounded retention for immutable, generation-scoped graph summaries.

Entries are kept as compressed JSON: an estate-scale roll-up is megabytes of
highly repetitive rows, and the byte bounds below apply to what is retained.
"""

from __future__ import annotations

import json
import threading
import time
import zlib
from collections import OrderedDict
from typing import Any, cast

_MAX_BYTES = 8 * 1024 * 1024
_MAX_ENTRY_BYTES = 1024 * 1024
_MAX_ENTRIES = 32
_TTL_SECONDS = 30
_LOCK = threading.Lock()
_CACHE: OrderedDict[tuple[Any, ...], tuple[float, bytes]] = OrderedDict()


def get(key: tuple[Any, ...]) -> dict[str, Any] | None:
    if len(repr(key)) > 4096:
        return None
    with _LOCK:
        now = time.monotonic()
        for old_key, (expires, _) in list(_CACHE.items()):
            if expires <= now:
                del _CACHE[old_key]
        entry = _CACHE.get(key)
        if entry is None:
            return None
        _CACHE.move_to_end(key)
        payload = entry[1]
    return cast(dict[str, Any], json.loads(zlib.decompress(payload)))


def put(key: tuple[Any, ...], value: dict[str, Any], *, ttl: float | None = None) -> None:
    if len(repr(key)) > 4096:
        return
    payload = zlib.compress(json.dumps(value, separators=(",", ":")).encode(), 1)
    if len(payload) > _MAX_ENTRY_BYTES:
        return
    with _LOCK:
        _CACHE[key] = (time.monotonic() + (_TTL_SECONDS if ttl is None else ttl), payload)
        _CACHE.move_to_end(key)
        while len(_CACHE) > _MAX_ENTRIES or sum(len(entry[1]) for entry in _CACHE.values()) > _MAX_BYTES:
            _CACHE.popitem(last=False)
