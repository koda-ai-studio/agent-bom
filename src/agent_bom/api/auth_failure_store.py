"""Atomic source-based authentication backoff, using the rate-limit database.

State contains only source addresses and counters, never credentials or tenants.
SQLite replicas must share the same database file; Postgres replicas share the
database through a small pool of their own. A state-store failure is propagated
to fail closed. Only a connection that was already dead is retried: a pool holds
several after a database restart, and each is one failed attempt rather than an
outage.
"""

from __future__ import annotations

import atexit
import math
import os
import sqlite3
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from contextlib import AbstractContextManager, contextmanager
from ipaddress import ip_network
from typing import Any, TypeVar

from agent_bom.api.postgres_common import _get_pool, _guard_rls_capable_role, _new_application_pool
from agent_bom.api.rate_limit_store import PostgresRateLimitStore
from agent_bom.api.storage_schema import ensure_postgres_schema_version
from agent_bom.config import POSTGRES_POOL_MAX_SIZE

_TABLE = """CREATE TABLE IF NOT EXISTS api_auth_failure_limits (
    source TEXT PRIMARY KEY, failures INTEGER NOT NULL, strikes INTEGER NOT NULL,
    window_start DOUBLE PRECISION NOT NULL, blocked_until DOUBLE PRECISION NOT NULL,
    updated_at DOUBLE PRECISION NOT NULL
)"""


_BUSY_TIMEOUT_SECONDS = 0.4
_RECEIPTS_PER_SOURCE_PER_MINUTE = 3
_RECEIPTS_PER_MINUTE = 100
_FIRST_RECEIPTS_PER_MINUTE = 400
_FIRST_RECEIPTS_PER_NETWORK_PER_MINUTE = 25
_T = TypeVar("_T")


class AuthFailureStore(ABC):
    @abstractmethod
    def transaction(self, source: str) -> AbstractContextManager[Any]:
        """Serialize one source and yield the backend SQL executor."""
        raise NotImplementedError

    def reader(self, source: str) -> AbstractContextManager[Any]:
        """Yield an executor for one source's state; backends may avoid write locks."""
        return self.transaction(source)

    def remaining(self, source: str, now: float) -> int:
        with self.reader(source) as execute:
            row = execute("SELECT blocked_until FROM api_auth_failure_limits WHERE source = ?", (source,)).fetchone()
        return max(0, math.ceil(float(row[0]) - now)) if row else 0

    def record(self, source: str, now: float, *, limit: int, base: int, maximum: int, count: int = 1) -> int:
        with self.transaction(source) as execute:
            execute("DELETE FROM api_auth_failure_limits WHERE updated_at < ? AND blocked_until < ?", (now - 3600, now))
            row = execute(
                "SELECT failures, strikes, window_start, blocked_until, updated_at FROM api_auth_failure_limits WHERE source = ?",
                (source,),
            ).fetchone()
            failures, strikes, start, blocked, updated = row or (0, 0, now, 0, now)
            if blocked > now:
                return math.ceil(blocked - now)
            if now - updated >= 3600:
                strikes = 0
            if now - start >= 60:
                failures, start = 0, now
            failures += count
            if failures >= limit:
                blocked = now + min(maximum, base * 2 ** min(strikes, 16))
                strikes += 1
                failures, start = 0, blocked
            execute(
                """INSERT INTO api_auth_failure_limits VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT (source) DO UPDATE SET failures=excluded.failures,
                strikes=excluded.strikes, window_start=excluded.window_start,
                blocked_until=excluded.blocked_until, updated_at=excluded.updated_at""",
                (source, failures, strikes, start, blocked, now),
            )
        return max(0, math.ceil(blocked - now))

    def audit_allowed(self, source: str, now: float) -> bool:
        # Global lock serializes the budgets across replicas. Repeat receipts share the
        # deployment ceiling. A source's first receipt in the window has a higher one,
        # limited per network, so a flood cannot erase other sources' only record, and
        # rotating sources still cannot grow the log without bound.
        with self.transaction("audit-budget") as execute:

            def bucket(name: str) -> tuple[int, float]:
                row = execute("SELECT failures, window_start FROM api_auth_failure_limits WHERE source = ?", (name,)).fetchone()
                return (row[0], row[1]) if row and now - row[1] < 60 else (0, now)

            buckets = {name: bucket(name) for name in ("audit:source:" + source, "audit:global")}
            source_count = buckets["audit:source:" + source][0]
            if source_count >= _RECEIPTS_PER_SOURCE_PER_MINUTE:
                return False
            if source_count:
                if buckets["audit:global"][0] >= _RECEIPTS_PER_MINUTE:
                    return False
            else:
                network = "audit:network:" + _receipt_network(source)
                buckets[network] = bucket(network)
                if (
                    buckets["audit:global"][0] >= _FIRST_RECEIPTS_PER_MINUTE
                    or buckets[network][0] >= _FIRST_RECEIPTS_PER_NETWORK_PER_MINUTE
                ):
                    return False
            for name, (count, start) in buckets.items():
                execute(
                    """INSERT INTO api_auth_failure_limits VALUES (?, ?, 0, ?, 0, ?)
                    ON CONFLICT (source) DO UPDATE SET failures=excluded.failures,
                    window_start=excluded.window_start, updated_at=excluded.updated_at""",
                    (name, count + 1, start, now),
                )
        return True


def _receipt_network(source: str) -> str:
    """Group a source for its share of first receipts: an IPv4 /16 or an IPv6 /48."""
    try:
        network = ip_network(source, strict=False)
    except ValueError:
        return source
    return str(network.supernet(new_prefix=16 if network.version == 4 else 48))


class SQLiteAuthFailureStore(AuthFailureStore):
    """One connection per worker thread, so one stalled transaction blocks no reader.

    WAL readers do not wait for the writer. A second writer waits at most the
    busy timeout. An in-memory database exists only on its one connection, and
    takes a bounded lock around that connection instead.
    """

    def __init__(self, path: str = ":memory:") -> None:
        self._path = path
        self._local = threading.local()
        self._memory_lock: threading.Lock | None = None
        self._memory_connection: sqlite3.Connection | None = None
        if path != ":memory:":
            descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
            os.close(descriptor)
            os.chmod(path, 0o600)
        connection = sqlite3.connect(path, check_same_thread=False, timeout=5)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute(_TABLE)
        connection.commit()
        if path == ":memory:":
            self._memory_lock = threading.Lock()
            self._memory_connection = connection
        else:
            connection.close()

    def _connection(self) -> sqlite3.Connection:
        if self._memory_connection is not None:
            return self._memory_connection
        connection = getattr(self._local, "connection", None)
        if connection is None:
            connection = sqlite3.connect(self._path, timeout=_BUSY_TIMEOUT_SECONDS)
            connection.execute(f"PRAGMA busy_timeout={int(_BUSY_TIMEOUT_SECONDS * 1000)}")
            self._local.connection = connection
        return connection

    @contextmanager
    def _memory_guard(self):
        if self._memory_lock is None:
            yield
            return
        if not self._memory_lock.acquire(timeout=_BUSY_TIMEOUT_SECONDS):
            raise TimeoutError("Authentication database capacity exhausted")
        try:
            yield
        finally:
            self._memory_lock.release()

    @contextmanager
    def reader(self, source: str):
        try:
            with self._memory_guard():
                yield self._connection().execute
        except sqlite3.OperationalError as exc:
            _raise_if_busy(exc)
            raise

    @contextmanager
    def transaction(self, source: str):
        try:
            with self._memory_guard():
                conn = self._connection()
                conn.execute("BEGIN IMMEDIATE")
                with conn:
                    yield conn.execute
        except sqlite3.OperationalError as exc:
            _raise_if_busy(exc)
            raise


def _raise_if_busy(exc: sqlite3.OperationalError) -> None:
    if getattr(exc, "sqlite_errorcode", 0) & 0xFF in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
        raise TimeoutError("Authentication database capacity exhausted") from exc


class DeadConnectionError(RuntimeError):
    """The database connection was already closed when this operation used it."""


def _is_dead_connection(exc: BaseException) -> bool:
    """A connection-class failure, by driver class name so SQLite installs need no driver."""
    return any(cls.__name__ == "OperationalError" for cls in type(exc).__mro__) and getattr(exc, "sqlstate", None) in {
        None,
        "57P01",
        "57P02",
        "57P03",
    }


_SQL_BOUNDS = "SET LOCAL statement_timeout = '400ms'; SET LOCAL lock_timeout = '400ms'"
# The source is bound as a quoted literal by the driver: several statements cannot take parameters.
_BOUNDED_READ = (
    "SET LOCAL statement_timeout = '400ms'; SET LOCAL lock_timeout = '400ms'; "
    "SELECT blocked_until FROM api_auth_failure_limits WHERE source = {}"
)
_AUTH_STATE_POOL_MAX_SIZE = 4
_auth_state_pool_lock = threading.Lock()
_auth_state_pool: tuple[Any, Any] | None = None


def _close_auth_state_pool() -> None:
    global _auth_state_pool
    with _auth_state_pool_lock:
        if _auth_state_pool is not None:
            _auth_state_pool[1].close()
        _auth_state_pool = None


def auth_state_pool() -> Any:
    """A small autocommit pool reserved for authentication state.

    Ingest, graph and report work hold the application pool for seconds at a
    time; admission must not queue behind them. Autocommit lets a read travel
    as one round trip. A new application pool, after a reset, replaces it.
    """
    global _auth_state_pool
    app_pool = _get_pool()
    with _auth_state_pool_lock:
        if _auth_state_pool is None or _auth_state_pool[0] is not app_pool:
            if _auth_state_pool is not None:
                _auth_state_pool[1].close()
            size = max(1, min(_AUTH_STATE_POOL_MAX_SIZE, POSTGRES_POOL_MAX_SIZE))
            _auth_state_pool = (app_pool, _new_application_pool(min_size=1, max_size=size, autocommit=True))
        pool = _auth_state_pool[1]
    _guard_rls_capable_role(pool)
    return pool


atexit.register(_close_auth_state_pool)


def _last_result(cursor: Any) -> Any:
    """The rows of the final statement in a multi-statement query."""
    while getattr(cursor, "description", True) is None and cursor.nextset():
        pass
    return cursor


class PostgresAuthFailureStore(AuthFailureStore):
    """A dedicated autocommit pool: admission is one round trip, writes take a transaction lock.

    Each round trip releases the interpreter lock and must win it back. Under a
    CPU-heavy ingest or graph read that wait dominates, so the hot path keeps
    the count of trips to one rather than six.
    """

    # One attempt per connection a pool can hold, within one operation's bound.
    _MAX_DEAD_CONNECTIONS = 32

    def __init__(self, pool: Any = None) -> None:
        self._pool = pool if pool is not None else auth_state_pool()

        with self._pool.connection() as conn:
            if ensure_postgres_schema_version(conn, "auth_failure_limits"):
                conn.execute(_TABLE)

    @contextmanager
    def _bounded(self):
        try:
            with self._pool.connection(timeout=_BUSY_TIMEOUT_SECONDS) as conn:
                yield conn
        except Exception as exc:  # broad-except: Classify optional-driver contention without importing it in SQLite installations.
            if getattr(exc, "sqlstate", None) in {"55P03", "57014"} or type(exc).__name__ == "PoolTimeout":
                raise TimeoutError("Authentication database capacity exhausted") from exc
            if _is_dead_connection(exc):
                raise DeadConnectionError("Authentication database connection closed") from exc
            raise

    @contextmanager
    def transaction(self, source: str):
        lock = int(PostgresRateLimitStore._advisory_key("auth:" + source))
        with self._bounded() as conn, conn.transaction():
            # One round trip: both bounds, then the source's lock.
            conn.execute(f"{_SQL_BOUNDS}; SELECT pg_advisory_xact_lock({lock})")

            def execute(sql, parameters):
                return conn.execute(sql.replace("?", "%s"), parameters)

            yield execute

    def _blocked_until(self, source: str) -> float | None:
        from psycopg import sql

        query = sql.SQL(_BOUNDED_READ).format(sql.Literal(source))
        with self._bounded() as conn:
            # A single implicit transaction: the bounds apply to the read and end with it.
            row = _last_result(conn.execute(query)).fetchone()
        return float(row[0]) if row else None

    def _past_dead_connections(self, operation: Callable[[], _T]) -> _T:
        """Run an operation, moving past connections the server has already closed.

        The pool discards a broken connection when it is returned. A failure
        that survives this loop is evidence about the database, not the pool.
        An interrupted write may repeat, which at worst counts a failure twice.
        """
        deadline = time.monotonic() + _BUSY_TIMEOUT_SECONDS
        attempts = 0
        while True:
            try:
                return operation()
            except DeadConnectionError:
                attempts += 1
                if attempts >= self._MAX_DEAD_CONNECTIONS or time.monotonic() >= deadline:
                    raise

    def remaining(self, source: str, now: float) -> int:
        blocked = self._past_dead_connections(lambda: self._blocked_until(source))
        return max(0, math.ceil(blocked - now)) if blocked is not None else 0

    def record(self, source: str, now: float, *, limit: int, base: int, maximum: int, count: int = 1) -> int:
        return self._past_dead_connections(
            lambda: super(PostgresAuthFailureStore, self).record(source, now, limit=limit, base=base, maximum=maximum, count=count)
        )

    def audit_allowed(self, source: str, now: float) -> bool:
        return self._past_dead_connections(lambda: super(PostgresAuthFailureStore, self).audit_allowed(source, now))
