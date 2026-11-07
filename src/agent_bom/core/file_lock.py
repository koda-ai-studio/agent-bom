"""Portable advisory file-lock primitives shared across worker processes.

The operating system drops every lock when its holder dies, so a crash can
never leave one behind.
"""

from __future__ import annotations

import errno
import os
import threading

# Filesystems without advisory-lock support (some network mounts) report these.
UNSUPPORTED_LOCK_ERRNOS = frozenset({errno.ENOLCK, errno.EOPNOTSUPP, errno.ENOTSUP, errno.EINVAL})

# Windows byte-range locks are exclusive only. A shared holder takes one free
# byte of this range; an exclusive holder takes the whole range in one call,
# which fails while any byte of it is held.
SHARED_SLOTS = 256

if os.name == "nt":  # pragma: no cover - exercised on Windows CI
    import msvcrt

    _LOCK_HELD_ERRNOS = frozenset({errno.EACCES, errno.EAGAIN, errno.EDEADLK})

    def lock_file_descriptor(fd: int, *, blocking: bool = True) -> None:
        if os.fstat(fd).st_size == 0:
            os.write(fd, b"\0")
        while True:
            os.lseek(fd, 0, os.SEEK_SET)
            try:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)  # type: ignore[attr-defined]
                return
            except OSError as exc:
                if exc.errno not in _LOCK_HELD_ERRNOS:
                    raise
                if not blocking:
                    raise BlockingIOError(errno.EAGAIN, "lock is held") from exc
                threading.Event().wait(0.05)

    def unlock_file_descriptor(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)  # type: ignore[attr-defined]

    def _try_lock_region(fd: int, start: int, length: int) -> bool:
        os.lseek(fd, start, os.SEEK_SET)
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, length)  # type: ignore[attr-defined]
            return True
        except OSError as exc:
            if exc.errno not in _LOCK_HELD_ERRNOS:
                raise
            return False

    def try_shared_lock(fd: int) -> bool:
        """Take a free slot, leaving the file position on it for ``release_lock``."""
        return any(_try_lock_region(fd, slot, 1) for slot in range(SHARED_SLOTS))

    def try_exclusive_lock(fd: int) -> bool:
        return _try_lock_region(fd, 0, SHARED_SLOTS)

    def release_lock(fd: int, *, exclusive: bool) -> None:
        """Release a lock from the ``try_*`` calls, if held, and close *fd*."""
        try:
            if exclusive:
                os.lseek(fd, 0, os.SEEK_SET)
            # A shared holder's position still sits on its slot.
            msvcrt.locking(fd, msvcrt.LK_UNLCK, SHARED_SLOTS if exclusive else 1)  # type: ignore[attr-defined]
        except OSError:
            # Closing the handle releases the lock anyway; nothing was held on a failed attempt.
            pass
        finally:
            os.close(fd)

else:
    import fcntl

    def lock_file_descriptor(fd: int, *, blocking: bool = True) -> None:
        fcntl.flock(fd, fcntl.LOCK_EX if blocking else fcntl.LOCK_EX | fcntl.LOCK_NB)

    def unlock_file_descriptor(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)

    def _try_flock(fd: int, mode: int) -> bool:
        try:
            fcntl.flock(fd, mode | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            return False

    def try_shared_lock(fd: int) -> bool:
        return _try_flock(fd, fcntl.LOCK_SH)

    def try_exclusive_lock(fd: int) -> bool:
        return _try_flock(fd, fcntl.LOCK_EX)

    def release_lock(fd: int, *, exclusive: bool) -> None:
        """Release a lock from the ``try_*`` calls, if held, and close *fd*.

        Close only: ``LOCK_UN`` would also drop the lock for a forked child or
        parent sharing this open file description.
        """
        del exclusive
        os.close(fd)
