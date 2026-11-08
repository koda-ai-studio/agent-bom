"""Rate limit store."""

from __future__ import annotations

import asyncio
import atexit
import hashlib
import logging
import threading
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from typing import Any

from agent_bom.api.postgres_common import _get_pool, _guard_rls_capable_role, _new_application_pool
from agent_bom.config import POSTGRES_POOL_MAX_SIZE

_logger = logging.getLogger(__name__)

# How long a request waits for the shared store, including this process's own
# scheduling. The database bounds its work at 400 ms; the longer wait covers
# CPU-heavy ingest and graph threads in the same process, which delay every
# thread here, so local load does not demote limits to per-process ones.
SHARED_STORE_TIMEOUT_SECONDS = 2.0
_POOL_WAIT_SECONDS = 0.4
SHARED_STORE_COOLDOWN_SECONDS = 5.0
SHARED_STORE_WARNING_INTERVAL_SECONDS = 60.0


_ADMISSION_POOL_MAX_SIZE = 4
_admission_pool: tuple[Any, Any] | None = None
_admission_pool_lock = threading.Lock()


def admission_state_pool() -> Any:
    """The small autocommit pool that authentication and rate-limit state share.

    Ingest, graph and report work hold the application pool for seconds at a
    time; admission checks must not queue behind them. Autocommit lets a check
    travel as one round trip, so each holds a connection only briefly. One pool
    keeps the role's connection budget: it adds at most four connections per
    process. A new application pool, after a reset, replaces it.
    """
    global _admission_pool
    app_pool = _get_pool()
    with _admission_pool_lock:
        if _admission_pool is None or _admission_pool[0] is not app_pool:
            if _admission_pool is not None:
                _admission_pool[1].close()
            size = max(1, min(_ADMISSION_POOL_MAX_SIZE, POSTGRES_POOL_MAX_SIZE))
            _admission_pool = (app_pool, _new_application_pool(min_size=1, max_size=size, autocommit=True))
        pool = _admission_pool[1]
    _guard_rls_capable_role(pool)
    return pool


def _close_admission_pool() -> None:
    global _admission_pool
    with _admission_pool_lock:
        if _admission_pool is not None:
            _admission_pool[1].close()
        _admission_pool = None


atexit.register(_close_admission_pool)

# Per-transaction bounds, so they hold behind a transaction-mode connection pooler.
_ADMISSION_BOUNDS = ("SET LOCAL statement_timeout = '400ms'", "SET LOCAL lock_timeout = '400ms'")


def _open_bounded(conn: Any, statements: Sequence[tuple[str, Any]], *, commit: bool) -> list[Any]:
    with conn.pipeline():
        conn.execute("BEGIN")
        for bound in _ADMISSION_BOUNDS:
            conn.execute(bound)
        cursors = [conn.execute(sql, params) for sql, params in statements]
        if commit:
            conn.execute("COMMIT")
    return cursors


def _roll_back(conn: Any) -> None:
    try:
        conn.execute("ROLLBACK")
    except Exception:  # broad-except: the connection may already be gone, and the pool discards it.
        _logger.debug("Rollback after a bounded admission query failed", exc_info=False)


def bounded_round_trip(conn: Any, statements: Sequence[tuple[str, Any]]) -> Any:
    """Run parameterised *statements* as one transaction in one network round trip.

    The statements are pipelined between BEGIN and COMMIT with 400 ms statement
    and lock bounds. Under a CPU-heavy ingest each round trip waits to win the
    interpreter lock back, so admission checks keep their count at one. Returns
    the last statement's cursor. *conn* must be in autocommit mode.
    """
    done = False
    try:
        cursor = _open_bounded(conn, statements, commit=True)[-1]
        done = True
        return cursor
    finally:
        if not done:
            _roll_back(conn)


@contextmanager
def bounded_transaction(conn: Any, statements: Sequence[tuple[str, Any]]) -> Iterator[list[Any]]:
    """Open a transaction with 400 ms bounds and run *statements* in its first round trip.

    The caller continues in the transaction; it commits on exit and rolls back on error.
    """
    done = False
    try:
        yield _open_bounded(conn, statements, commit=False)
        conn.execute("COMMIT")
        done = True
    finally:
        if not done:
            _roll_back(conn)


class InMemoryRateLimitStore:
    """Process-local sliding-window limiter state."""

    _MAX_ENTRIES = 10_000
    _INLINE_MAX_HITS = 256

    def __init__(self, window_seconds: int = 60) -> None:
        self._window = window_seconds
        self._hits: dict[str, list[float]] = {}
        self._last_cleanup = time.time()
        self._lock = threading.RLock()

    def _cleanup(self, now: float) -> None:
        """Prune stale entries to prevent unbounded memory growth."""
        with self._lock:
            if now - self._last_cleanup < self._window:
                return
            self._last_cleanup = now
            stale = [k for k, v in self._hits.items() if not v or v[-1] < now - self._window]
            for k in stale:
                del self._hits[k]
            if len(self._hits) > self._MAX_ENTRIES:
                overflow = len(self._hits) - self._MAX_ENTRIES
                oldest_keys = sorted(self._hits, key=lambda key: self._hits[key][-1] if self._hits[key] else 0.0)[:overflow]
                for key in oldest_keys:
                    del self._hits[key]
                _logger.warning(
                    "In-memory rate limiter pruned %s oldest buckets to stay under %s entries",
                    overflow,
                    self._MAX_ENTRIES,
                )

    def hit(self, key: str, now: float) -> tuple[int, int]:
        """Record a request and return (hit_count, reset_epoch)."""
        with self._lock:
            self._cleanup(now)
            return self._hit_locked(key, now)

    def _hit_locked(self, key: str, now: float) -> tuple[int, int]:
        timestamps = [t for t in self._hits.get(key, []) if now - t < self._window]
        timestamps.append(now)
        self._hits[key] = timestamps
        return len(timestamps), int(timestamps[0] + self._window)

    def _try_hit_bounded(self, key: str, now: float) -> tuple[int, int] | None:
        """Try a small memory-only hit without waiting or scanning other buckets."""
        if not self._lock.acquire(blocking=False):
            return None
        try:
            if (
                now - self._last_cleanup >= self._window
                or len(self._hits.get(key, [])) >= self._INLINE_MAX_HITS
                or (key not in self._hits and len(self._hits) >= self._MAX_ENTRIES)
            ):
                return None
            return self._hit_locked(key, now)
        finally:
            self._lock.release()

    def consume_if_below(self, key: str, now: float, limit: int) -> tuple[bool, int, int]:
        """Atomically consume one sliding-window unit when below ``limit``."""

        with self._lock:
            self._cleanup(now)
            timestamps = [timestamp for timestamp in self._hits.get(key, []) if now - timestamp < self._window]
            accepted = len(timestamps) < limit
            if accepted:
                timestamps.append(now)
                self._hits[key] = timestamps
            reset_at = int((timestamps[0] if timestamps else now) + self._window)
            return accepted, len(timestamps), reset_at

    def count(self, key: str, now: float) -> int:
        """Return current sliding-window usage without consuming a unit."""

        with self._lock:
            self._cleanup(now)
            timestamps = [timestamp for timestamp in self._hits.get(key, []) if now - timestamp < self._window]
            if timestamps:
                self._hits[key] = timestamps
            else:
                self._hits.pop(key, None)
            return len(timestamps)


# The statements of one operation reach the server as this thread sends them, so
# under a CPU-heavy ingest its transaction can stay open for hundreds of
# milliseconds. A hit therefore takes no lock another hit could wait on: pruning
# skips rows another transaction is already deleting.
_PRUNE_ALL = "DELETE FROM api_rate_limit_hits WHERE ctid IN (SELECT ctid FROM api_rate_limit_hits WHERE hit_at < %s FOR UPDATE SKIP LOCKED)"
_PRUNE_BUCKET = (
    "DELETE FROM api_rate_limit_hits WHERE ctid IN "
    "(SELECT ctid FROM api_rate_limit_hits WHERE bucket_key = %s AND hit_at < %s FOR UPDATE SKIP LOCKED)"
)
_LOCK = "SELECT pg_advisory_xact_lock(%s)"
# Counts the window as it stood, then records the hit when below the limit (always, without one).
_RECORD = """
WITH current_window AS (
    SELECT COUNT(*) AS hits, MIN(hit_at) AS oldest
    FROM api_rate_limit_hits WHERE bucket_key = %(key)s AND hit_at >= %(start)s
), added AS (
    INSERT INTO api_rate_limit_hits (bucket_key, hit_at)
    SELECT %(key)s, %(now)s FROM current_window
    WHERE %(limit)s::bigint IS NULL OR hits < %(limit)s::bigint
    RETURNING 1
)
SELECT hits, oldest, (SELECT COUNT(*) FROM added) FROM current_window
"""
_COUNT = "SELECT COUNT(*) FROM api_rate_limit_hits WHERE bucket_key = %s AND hit_at >= %s"


class PostgresRateLimitStore:
    """Shared sliding-window limiter backed by Postgres for horizontal scaling.

    It uses a small autocommit admission pool of its own.
    Each operation is one round trip and one transaction, bounded to 400 ms by
    the database. A budget consumed with ``consume_if_below`` is exact across
    replicas; a request hit can miss hits still in flight on other replicas.
    """

    def __init__(self, window_seconds: int = 60, pool: Any = None) -> None:
        self._window = window_seconds
        self._pool = pool if pool is not None else admission_state_pool()
        self._next_global_prune = 0.0
        self._init_tables()

    def _init_tables(self) -> None:
        from agent_bom.api.storage_schema import ensure_postgres_schema_version

        with self._pool.connection() as conn:
            if not ensure_postgres_schema_version(conn, "rate_limits"):
                return
            conn.execute("""
                CREATE TABLE IF NOT EXISTS api_rate_limit_hits (
                    bucket_key TEXT NOT NULL,
                    hit_at DOUBLE PRECISION NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_api_rate_limit_hits_bucket_hit_at ON api_rate_limit_hits (bucket_key, hit_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_api_rate_limit_hits_hit_at ON api_rate_limit_hits (hit_at)")

    def _run(self, statements: list[tuple[str, Any]]) -> Any:
        with self._pool.connection(timeout=_POOL_WAIT_SECONDS) as conn:
            return bounded_round_trip(conn, statements).fetchone()

    def _consume(self, key: str, now: float, limit: int | None) -> tuple[int, float | None, bool]:
        """Prune, count and conditionally record one hit; returns (prior hits, oldest, added)."""
        start = now - self._window
        statements: list[tuple[str, Any]] = []
        # Buckets that never return are trimmed by a table-wide prune at most
        # once per window per process.
        if now >= self._next_global_prune:
            self._next_global_prune = now + self._window
            statements.append((_PRUNE_ALL, (start,)))
        if limit is not None:
            # An exact budget serializes its bucket; a request limit stays lock-free.
            statements.append((_LOCK, (self._advisory_key(key),)))
        statements += [
            (_PRUNE_BUCKET, (key, start)),
            (_RECORD, {"key": key, "start": start, "now": now, "limit": limit}),
        ]
        row = self._run(statements)
        hits = int(row[0]) if row and row[0] is not None else 0
        oldest = float(row[1]) if row and row[1] is not None else None
        return hits, oldest, bool(row and row[2])

    def hit(self, key: str, now: float) -> tuple[int, int]:
        """Record a request and return (hit_count, reset_epoch)."""
        hits, oldest, _added = self._consume(key, now, None)
        oldest_at = min(oldest, now) if oldest is not None else now
        return hits + 1, int(oldest_at + self._window)

    @staticmethod
    def _advisory_key(key: str) -> int:
        digest = hashlib.sha256(f"rate-limit:{key}".encode()).digest()
        return int.from_bytes(digest[:8], "big", signed=True)

    def consume_if_below(self, key: str, now: float, limit: int) -> tuple[bool, int, int]:
        """Atomically consume one unit under the bucket's transaction advisory lock."""

        hits, oldest, added = self._consume(key, now, limit)
        oldest_at = oldest if oldest is not None else now
        return added, hits + int(added), int(oldest_at + self._window)

    def count(self, key: str, now: float) -> int:
        """Return current sliding-window usage without consuming a unit."""

        row = self._run([(_COUNT, (key, now - self._window))])
        return int(row[0]) if row and row[0] is not None else 0


class FailOpenRateLimitStore:
    """Shared limiter that degrades to process-local counting while its backend is unavailable.

    Rate limiting is abuse protection, not an authorization boundary, so a
    shared-store error or stall must not turn every request (including probes)
    into a 500 or a hang. Each degraded request is still counted against the
    in-memory window; after ``cooldown_seconds`` the shared store is retried.
    """

    def __init__(
        self,
        primary: Any,
        *,
        window_seconds: int = 60,
        timeout_seconds: float = SHARED_STORE_TIMEOUT_SECONDS,
        cooldown_seconds: float = SHARED_STORE_COOLDOWN_SECONDS,
    ) -> None:
        self.primary = primary
        self.fallback = InMemoryRateLimitStore(window_seconds=window_seconds)
        self._timeout = timeout_seconds
        self._cooldown = cooldown_seconds
        self._degraded_until = 0.0
        self._last_warning = float("-inf")
        self._lock = threading.Lock()

    def _degrade(self, exc: BaseException) -> None:
        current = time.monotonic()
        with self._lock:
            self._degraded_until = current + self._cooldown
            should_log = current - self._last_warning >= SHARED_STORE_WARNING_INTERVAL_SECONDS
            if should_log:
                self._last_warning = current
        if should_log:
            _logger.warning(
                "Shared rate-limit store unavailable (%s); enforcing process-local limits until it recovers",
                type(exc).__name__,
            )

    async def hit_async(self, key: str, now: float) -> tuple[int, int]:
        if time.monotonic() >= self._degraded_until:
            try:
                return await asyncio.wait_for(asyncio.to_thread(self.primary.hit, key, now), self._timeout)
            except Exception as exc:  # noqa: BLE001 - any backend failure degrades to local limits
                self._degrade(exc)
        return await record_rate_limit_hit(self.fallback, key, now)


async def record_rate_limit_hit(
    store: InMemoryRateLimitStore | PostgresRateLimitStore | FailOpenRateLimitStore, key: str, now: float
) -> tuple[int, int]:
    """Keep SQL, cleanup, large buckets and contended locks off the event loop."""
    if isinstance(store, FailOpenRateLimitStore):
        return await store.hit_async(key, now)
    if type(store) is InMemoryRateLimitStore:
        result = store._try_hit_bounded(key, now)
        if result is not None:
            return result
    return await asyncio.to_thread(store.hit, key, now)
