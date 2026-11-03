"""Cluster leader election for control-plane background loops.

A loop that writes shared durable state or drives cloud side effects must run
on exactly one replica of a clustered (Postgres) control plane.
``cluster_leader_lock`` returns a lock that holds a session-level
``pg_try_advisory_lock`` on a dedicated pooled connection when Postgres is the
control-plane store, and an always-leader lock on a single node (SQLite).

Postgres releases a session's advisory locks when the session ends, so a
replica that exits or loses its connection hands leadership to the next
replica that polls. The holder confirms in ``pg_locks`` that its session still
holds the lock before every run; after a loss it closes the dead connection
and either re-acquires on a fresh one or stands by. ``ensure`` fails closed:
an unreachable database means "not leader", so a gated loop skips its run
rather than risk a duplicate.

Loops that only fill a process-local cache (posture-count precompute, exec read
prewarm) are deliberately not gated: every replica must warm its own memory.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from typing import Any, Protocol

from agent_bom.api import postgres_common
from agent_bom.api.storage_schema import postgres_deployment_configured

try:
    from psycopg import Error as _DriverError
except ImportError:  # psycopg ships only with the Postgres extra
    _DriverError = OSError  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)

# Distinct bigint keys in the one advisory-lock namespace; never reuse a value.
SCHEDULER_LEADER_LOCK_ID = 4_197_042_001
ADVISORY_REMATCH_LEADER_LOCK_ID = 4_197_042_002
SIDE_SCAN_SCHEDULER_LEADER_LOCK_ID = 4_197_042_003

#: How often a standby replica retries for leadership, capped by the loop's own interval.
STANDBY_POLL_SECONDS: float = 60.0

_HOLDS_LOCK_SQL = (
    "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND granted"
    " AND pid = pg_backend_pid() AND objsubid = 1"
    " AND ((classid::bigint << 32) | objid::bigint) = %s)"
)


class LeaderLock(Protocol):
    name: str

    def ensure(self) -> bool:
        """Return whether this replica leads right now, acquiring when free."""

    def release(self) -> None:
        """Give up leadership; safe to call when not leader."""


class AlwaysLeader:
    """Single-node control plane: the only replica always leads."""

    def __init__(self, name: str) -> None:
        self.name = name

    def ensure(self) -> bool:
        return True

    def release(self) -> None:
        return None


class PostgresAdvisoryLeaderLock:
    """Session-level ``pg_try_advisory_lock`` held on one checked-out pooled connection."""

    def __init__(self, lock_id: int, name: str, *, pool_factory: Callable[[], Any] | None = None) -> None:
        self.lock_id = lock_id
        self.name = name
        self._pool_factory = pool_factory or postgres_common._get_pool
        self._pool: Any = None
        self._conn: Any = None
        self._mutex = threading.Lock()

    def ensure(self) -> bool:
        with self._mutex:
            if self._conn is not None:
                if self._still_held():
                    return True
                logger.warning("%s leader lock lost with its connection; standing by until it can be re-acquired", self.name)
                self._discard()
            return self._try_acquire()

    def release(self) -> None:
        with self._mutex:
            if self._conn is None:
                return
            try:
                self._conn.execute("SELECT pg_advisory_unlock(%s)", (self.lock_id,))
                self._conn.commit()
                self._pool.putconn(self._conn)
                logger.info("%s leader lock released", self.name)
            except Exception:  # broad-except: shutdown must not raise; closing the session releases the lock instead
                logger.error("%s leader lock release failed; closing its connection", self.name)
                self._close_and_return(self._pool, self._conn)
            self._pool = self._conn = None

    def _still_held(self) -> bool:
        try:
            row = self._conn.execute(_HOLDS_LOCK_SQL, (self.lock_id,)).fetchone()
            self._conn.commit()
        except Exception:  # broad-except: any driver or network failure means the session, and the lock, may be gone
            return False
        return bool(row and row[0])

    def _try_acquire(self) -> bool:
        pool = conn = None
        try:
            pool = self._pool_factory()
            conn = pool.getconn()
            row = conn.execute("SELECT pg_try_advisory_lock(%s)", (self.lock_id,)).fetchone()
            # Session-level lock survives commit; committing keeps the session out of idle-in-transaction.
            conn.commit()
        except Exception:  # broad-except: an unreachable database fails closed as "not leader"
            logger.error("%s leader lock could not be acquired; skipping this run", self.name)
            if conn is not None:
                self._close_and_return(pool, conn)
            return False
        if row and bool(row[0]):
            self._pool, self._conn = pool, conn
            logger.info("%s leader lock acquired", self.name)
            return True
        pool.putconn(conn)
        return False

    def _discard(self) -> None:
        self._close_and_return(self._pool, self._conn)
        self._pool = self._conn = None

    @staticmethod
    def _close_and_return(pool: Any, conn: Any) -> None:
        """Close first so a session that might still hold the lock never re-enters the pool."""
        for step in (conn.close, lambda: pool.putconn(conn)):
            try:
                step()
            except (_DriverError, OSError, RuntimeError, ValueError):
                logger.debug("leader lock connection cleanup step skipped")


def cluster_leader_lock(lock_id: int, name: str) -> LeaderLock:
    """Advisory leader lock on a Postgres control plane, always-leader on a single node."""
    if postgres_deployment_configured():
        return PostgresAdvisoryLeaderLock(lock_id, name)
    return AlwaysLeader(name)


def standby_poll_seconds(interval_seconds: float) -> float:
    """Retry cadence for a replica that is not leader: no slower than the loop itself."""
    return max(0.0, min(float(interval_seconds), STANDBY_POLL_SECONDS))


__all__ = [
    "ADVISORY_REMATCH_LEADER_LOCK_ID",
    "AlwaysLeader",
    "LeaderLock",
    "PostgresAdvisoryLeaderLock",
    "SCHEDULER_LEADER_LOCK_ID",
    "SIDE_SCAN_SCHEDULER_LEADER_LOCK_ID",
    "STANDBY_POLL_SECONDS",
    "cluster_leader_lock",
    "standby_poll_seconds",
]
