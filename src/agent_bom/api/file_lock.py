"""Portable advisory file locks shared by API stores that coordinate across worker processes."""

from __future__ import annotations

import logging
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from agent_bom.core.file_lock import UNSUPPORTED_LOCK_ERRNOS, lock_file_descriptor, unlock_file_descriptor

__all__ = ["exclusive_file_lock", "lock_file_descriptor", "unlock_file_descriptor"]

logger = logging.getLogger(__name__)


@contextmanager
def exclusive_file_lock(path: str | Path, *, blocking: bool = True) -> Iterator[bool]:
    """Hold an exclusive advisory lock on *path* across processes; yield whether it is held.

    Where the filesystem cannot lock, yield ``False`` instead of failing the
    caller, which then keeps only its in-process guarantees. With
    ``blocking=False`` a lock held elsewhere raises ``BlockingIOError``.
    """
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            lock_file_descriptor(fd, blocking=blocking)
        except BlockingIOError:
            raise
        except OSError as exc:
            if exc.errno not in UNSUPPORTED_LOCK_ERRNOS:
                raise
            logger.warning("Advisory file locks are unavailable for %s; using in-process locking only", path)
            yield False
            return
        try:
            yield True
        finally:
            unlock_file_descriptor(fd)
    finally:
        os.close(fd)
