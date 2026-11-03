"""Per-key process fences for the SQLite idempotency store.

A thread stripe lock plus an OS file lock serialize one key across threads
and API worker processes. ``commit_claim`` holds the fence for its durable
action; ``claim`` only ever *tries* it, so a retry or a stripe neighbour never
waits behind another request's commit.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from collections.abc import Iterator
from contextlib import contextmanager

from agent_bom.api.file_lock import lock_file_descriptor as _lock_file_descriptor
from agent_bom.api.file_lock import unlock_file_descriptor as _unlock_file_descriptor

_SQLITE_CLAIM_LOCK_STRIPE_COUNT = 256
_SQLITE_CLAIM_LOCKS = tuple(threading.Lock() for _ in range(_SQLITE_CLAIM_LOCK_STRIPE_COUNT))


class SQLiteClaimFenceMixin:
    _db_path: str

    def _claim_lock_digest(self, endpoint: str, tenant_id: str, source_id: str, idempotency_key: str) -> str:
        identity = json.dumps(
            [os.path.abspath(self._db_path), endpoint, tenant_id, source_id, idempotency_key],
            separators=(",", ":"),
            ensure_ascii=True,
        )
        return hashlib.sha256(identity.encode("utf-8")).hexdigest()

    def _claim_lock(self, endpoint: str, tenant_id: str, source_id: str, idempotency_key: str) -> threading.Lock:
        digest = self._claim_lock_digest(endpoint, tenant_id, source_id, idempotency_key)
        return _SQLITE_CLAIM_LOCKS[int(digest[:2], 16)]

    @contextmanager
    def _claim_file_lock(
        self,
        endpoint: str,
        tenant_id: str,
        source_id: str,
        idempotency_key: str,
        *,
        blocking: bool = True,
    ) -> Iterator[None]:
        """Fence one SQLite idempotency key across API worker processes.

        With ``blocking=False`` a fence held elsewhere raises ``BlockingIOError``.
        """

        if self._db_path == ":memory:":
            yield
            return
        database_path = os.path.abspath(self._db_path)
        lock_directory = f"{database_path}.idempotency-locks"
        os.makedirs(lock_directory, mode=0o700, exist_ok=True)
        digest = self._claim_lock_digest(endpoint, tenant_id, source_id, idempotency_key)
        # Fixed stripes prevent one lock artifact per idempotency key while
        # retaining concurrency across unrelated keys.
        lock_path = os.path.join(lock_directory, f"{digest[:2]}.lock")
        flags = os.O_CREAT | os.O_RDWR
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(lock_path, flags, 0o600)
        try:
            _lock_file_descriptor(fd, blocking=blocking)
            try:
                yield
            finally:
                _unlock_file_descriptor(fd)
        finally:
            os.close(fd)

    @contextmanager
    def _try_claim_fence(self, endpoint: str, tenant_id: str, source_id: str, idempotency_key: str) -> Iterator[bool]:
        thread_lock = self._claim_lock(endpoint, tenant_id, source_id, idempotency_key)
        if not thread_lock.acquire(blocking=False):
            yield False
            return
        try:
            file_fence = self._claim_file_lock(endpoint, tenant_id, source_id, idempotency_key, blocking=False)
            try:
                file_fence.__enter__()
            except BlockingIOError:
                yield False
                return
            try:
                yield True
            finally:
                file_fence.__exit__(None, None, None)
        finally:
            thread_lock.release()
