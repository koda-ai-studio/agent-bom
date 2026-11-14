"""Bounded WAL initialization shared by thread-local SQLite stores."""

from __future__ import annotations

import sqlite3
from contextlib import ExitStack

from agent_bom.core.settings import env_int
from agent_bom.storage.sqlite_wal import enable_wal

# Python's own sqlite3 default lock wait. A request that cannot get the lock in
# this window answers 503 with Retry-After instead of holding a worker thread.
_DEFAULT_BUSY_TIMEOUT_MS = 5_000
_MIN_BUSY_TIMEOUT_MS = 100
_MAX_BUSY_TIMEOUT_MS = 120_000


def api_sqlite_busy_timeout_ms() -> int:
    """How long an API SQLite connection waits for a lock (``AGENT_BOM_API_SQLITE_BUSY_TIMEOUT_MS``)."""
    value = env_int("AGENT_BOM_API_SQLITE_BUSY_TIMEOUT_MS", None, on_invalid="default")
    if value is None:
        return _DEFAULT_BUSY_TIMEOUT_MS
    return min(max(value, _MIN_BUSY_TIMEOUT_MS), _MAX_BUSY_TIMEOUT_MS)


def open_wal_connection(path: str, *, normal_sync: bool = False) -> sqlite3.Connection:
    """Open a WAL connection whose lock waits are bounded by the API busy timeout.

    SQLite may return SQLITE_BUSY immediately when concurrent connections
    switch journal mode, even with a busy handler. Retry that specific startup
    contention within the same budget; propagate every other error and close
    the failed connection.
    """
    busy_timeout_ms = api_sqlite_busy_timeout_ms()
    with ExitStack() as cleanup:
        conn = sqlite3.connect(path, timeout=0.05, check_same_thread=False)
        cleanup.callback(conn.close)
        enable_wal(conn, wait_seconds=busy_timeout_ms / 1000)
        conn.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")
        if normal_sync:
            conn.execute("PRAGMA synchronous=NORMAL")
        cleanup.pop_all()
        return conn
