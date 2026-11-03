"""Bounded, short-TTL memory of successful API-key verifications.

The scrypt derivation in ``verify_api_key`` costs tens of milliseconds of CPU
per call. This cache lets a key that verified recently skip it, and nothing
else: the caller still re-reads the stored record and re-checks revocation,
expiry, rotation and operator retirement on every request.

Nothing secret is retained. An entry is keyed by an HMAC of the presented key
under a random per-process secret, and records only the matched ``key_id``
plus an HMAC fingerprint of the stored ``(key_id, salt, hash)`` triple, so a
replaced credential for the same ``key_id`` never matches. Failed
verifications are never stored.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass

from agent_bom import config

MAX_TTL_SECONDS = 60.0


@dataclass(frozen=True)
class _Entry:
    key_id: str
    fingerprint: bytes
    expires_at: float


_SECRET = secrets.token_bytes(32)
_lock = threading.Lock()
_entries: OrderedDict[bytes, _Entry] = OrderedDict()
_now = time.monotonic


def _ttl_seconds() -> float:
    return min(max(float(config.API_KEY_VERIFY_CACHE_TTL_SECONDS), 0.0), MAX_TTL_SECONDS)


def _max_entries() -> int:
    return max(int(config.API_KEY_VERIFY_CACHE_MAX_ENTRIES), 0)


def presented_key_digest(raw_key: str) -> bytes:
    """Cache key for a presented credential; irreversible without the process secret."""
    return hmac.new(_SECRET, b"presented\x00" + raw_key.encode(), hashlib.sha256).digest()


def record_fingerprint(key_id: str, key_salt: str, key_hash: str) -> bytes:
    """Binds an entry to one exact stored credential without retaining its hash."""
    material = "\x00".join((key_id, key_salt, key_hash)).encode()
    return hmac.new(_SECRET, b"record\x00" + material, hashlib.sha256).digest()


def lookup(digest: bytes) -> tuple[str, bytes] | None:
    """Return ``(key_id, fingerprint)`` for a live entry, dropping it once stale."""
    if _ttl_seconds() <= 0 or _max_entries() <= 0:
        return None
    with _lock:
        entry = _entries.get(digest)
        if entry is None:
            return None
        if _now() >= entry.expires_at:
            del _entries[digest]
            return None
        _entries.move_to_end(digest)
        return entry.key_id, entry.fingerprint


def remember(digest: bytes, key_id: str, fingerprint: bytes, *, not_after_seconds: float | None) -> None:
    """Record a successful verification for at most the TTL and never past the key's expiry."""
    lifetime = _ttl_seconds()
    if not_after_seconds is not None:
        lifetime = min(lifetime, not_after_seconds)
    limit = _max_entries()
    if lifetime <= 0 or limit <= 0:
        return
    with _lock:
        _entries[digest] = _Entry(key_id=key_id, fingerprint=fingerprint, expires_at=_now() + lifetime)
        _entries.move_to_end(digest)
        while len(_entries) > limit:
            _entries.popitem(last=False)


def forget(digest: bytes) -> None:
    with _lock:
        _entries.pop(digest, None)


def clear() -> None:
    with _lock:
        _entries.clear()


def size() -> int:
    with _lock:
        return len(_entries)
