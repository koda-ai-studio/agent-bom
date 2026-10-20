"""Portable advisory file locks shared by API stores that coordinate across worker processes."""

from __future__ import annotations

import errno
import logging
import os
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

logger = logging.getLogger(__name__)

# Filesystems without advisory-lock support (some network mounts) report these.
_UNSUPPORTED_LOCK_ERRNOS = frozenset({errno.ENOLCK, errno.EOPNOTSUPP, errno.ENOTSUP, errno.EINVAL})

if os.name == "nt":  # pragma: no cover - exercised on Windows CI
    import msvcrt

    def lock_file_descriptor(fd: int) -> None:
        if os.fstat(fd).st_size == 0:
            os.write(fd, b"\0")
        while True:
            os.lseek(fd, 0, os.SEEK_SET)
            try:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)  # type: ignore[attr-defined]
                return
            except OSError as exc:
                if exc.errno not in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
                    raise
                threading.Event().wait(0.05)

    def unlock_file_descriptor(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)  # type: ignore[attr-defined]

else:
    import fcntl

    def lock_file_descriptor(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_EX)

    def unlock_file_descriptor(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)


@contextmanager
def exclusive_file_lock(path: str | Path) -> Iterator[bool]:
    """Hold an exclusive advisory lock on *path* across processes; yield whether it is held.

    Where the filesystem cannot lock, yield ``False`` instead of failing the
    caller, which then keeps only its in-process guarantees.
    """
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            lock_file_descriptor(fd)
        except OSError as exc:
            if exc.errno not in _UNSUPPORTED_LOCK_ERRNOS:
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
