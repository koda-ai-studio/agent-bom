"""Open the database a sync writes to: in place when one exists, built aside when none does.

Writing through WAL costs about 19 bytes per byte stored on a first sync (each
small commit rewrites the same B-tree pages and every checkpoint flushes), which
is what a slow CI disk pays for. A first build has no readers and nothing to
lose, so it runs against a private file with no flushes and no write-ahead log,
and only a finished file is renamed into place. A crash leaves a stray build
file, never a torn database. An existing database keeps the crash-safe settings.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import tempfile
import time
from pathlib import Path
from types import TracebackType

from agent_bom.db import schema

_logger = logging.getLogger(__name__)

BUILD_INFIX = ".build-"
# Long enough that a slow live build is never swept by a concurrent first run.
STALE_BUILD_SECONDS = 6 * 3600
_BUILD_PRAGMAS = (
    "PRAGMA journal_mode = MEMORY",
    "PRAGMA synchronous = OFF",
    "PRAGMA cache_size = -262144",
    "PRAGMA temp_store = MEMORY",
    "PRAGMA locking_mode = EXCLUSIVE",
)
# Durability is untouched, and each flush costs a slow disk far more than a write:
# refreshing 60,000 advisories took 163 flushes at the default of every 1,000 pages, 7 here.
_UPDATE_PRAGMAS = ("PRAGMA wal_autocheckpoint = 16384",)


def build_files(db_path: Path) -> list[Path]:
    """Build files beside ``db_path``, finished or abandoned."""
    return sorted(db_path.parent.glob(f"{db_path.name}{BUILD_INFIX}*"))


def _sweep_abandoned_builds(db_path: Path) -> None:
    cutoff = time.time() - STALE_BUILD_SECONDS
    for path in build_files(db_path):
        try:
            if path.stat().st_mtime < cutoff:
                path.unlink()
        except OSError as exc:
            _logger.debug("Could not remove abandoned vuln DB build %s: %s", path.name, exc)


def _unlink_quietly(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError as exc:
        _logger.debug("Could not remove %s: %s", path.name, exc)


class SyncSession:
    """A sync's connection and how to finish it; ``close(exc)`` takes the exception that ended the sync, if any."""

    def __init__(self, conn: sqlite3.Connection, target: Path, build: Path | None) -> None:
        self.conn = conn
        self._target = target
        self._build = build

    def __enter__(self) -> SyncSession:
        return self

    def __exit__(self, _type: type[BaseException] | None, exc: BaseException | None, _traceback: TracebackType | None) -> None:
        self.close(exc)

    def close(self, exc: BaseException | None) -> None:
        publish = self._build is not None and self._worth_publishing(exc)
        # Fold the (potentially large) -wal back into the main DB so concurrent readers don't race a big write-ahead log right after a sync.
        try:
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.Error as checkpoint_error:
            _logger.debug("WAL checkpoint after sync_db skipped: %s", checkpoint_error)
        self.conn.close()
        if self._build is None:
            return
        if publish:
            self._publish(self._build)
        else:
            _unlink_quietly(self._build)

    def _worth_publishing(self, exc: BaseException | None) -> bool:
        """A network or parsing failure leaves finished sources worth keeping, as an in-place sync does.

        A database error or an interrupt leaves nothing to trust. With no finished
        source there is nothing to keep, and the next run should build aside again.
        """
        if exc is None:
            return True
        if not isinstance(exc, Exception) or isinstance(exc, sqlite3.Error):
            return False
        return self.conn.execute("SELECT 1 FROM sync_meta LIMIT 1").fetchone() is not None

    def _publish(self, build: Path) -> None:
        try:
            finished = sqlite3.connect(str(build))
            try:
                finished.execute("PRAGMA journal_mode = WAL").fetchone()
            finally:
                finished.close()
            with open(build, "rb+") as handle:
                os.fsync(handle.fileno())
            if not self._target.exists():
                # A log left by a deleted database must not be replayed into this one.
                for suffix in ("-wal", "-shm"):
                    _unlink_quietly(self._target.with_name(self._target.name + suffix))
            os.replace(build, self._target)
        except (OSError, sqlite3.Error) as exc:
            # Windows refuses to replace a file another process holds open: that process has a database, so this one is surplus.
            _logger.warning("Could not publish the new vuln DB at %s: %s", self._target, exc)
            _unlink_quietly(build)


def open_sync_session(db_path: Path) -> SyncSession:
    """Open ``db_path`` for a sync; a missing database is built aside and published on close."""
    if db_path.exists():
        # The update rewrites the database, so it is the right place to pay for a full integrity check — and the only place that still does.
        conn = schema.init_db(db_path, verify_integrity=True)
        for pragma in _UPDATE_PRAGMAS:
            conn.execute(pragma)
        return SyncSession(conn, db_path, None)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    _sweep_abandoned_builds(db_path)
    handle, name = tempfile.mkstemp(dir=db_path.parent, prefix=f"{db_path.name}{BUILD_INFIX}")
    os.close(handle)
    build = Path(name)
    try:
        conn = schema.init_db(build)
        for pragma in _BUILD_PRAGMAS:
            conn.execute(pragma)
    except (OSError, sqlite3.Error):
        _unlink_quietly(build)
        raise
    return SyncSession(conn, db_path, build)
