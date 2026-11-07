"""Atomic source-based authentication backoff, using the rate-limit database.

State contains only source addresses and counters, never credentials or tenants.
SQLite replicas must share the same database file; Postgres replicas share the
existing rate-limit pool. A state-store failure is propagated to fail closed.
"""

from __future__ import annotations

import math
import os
import sqlite3
import threading
from abc import ABC, abstractmethod
from contextlib import AbstractContextManager, contextmanager
from typing import Any

from agent_bom.api.rate_limit_store import PostgresRateLimitStore
from agent_bom.api.storage_schema import ensure_postgres_schema_version

_TABLE = """CREATE TABLE IF NOT EXISTS api_auth_failure_limits (
    source TEXT PRIMARY KEY, failures INTEGER NOT NULL, strikes INTEGER NOT NULL,
    window_start DOUBLE PRECISION NOT NULL, blocked_until DOUBLE PRECISION NOT NULL,
    updated_at DOUBLE PRECISION NOT NULL
)"""


class AuthFailureStore(ABC):
    @abstractmethod
    def transaction(self, source: str) -> AbstractContextManager[Any]:
        """Serialize one source and yield the backend SQL executor."""
        raise NotImplementedError

    def remaining(self, source: str, now: float) -> int:
        with self.transaction(source) as execute:
            row = execute("SELECT blocked_until FROM api_auth_failure_limits WHERE source = ?", (source,)).fetchone()
        return max(0, math.ceil(float(row[0]) - now)) if row else 0

    def record(self, source: str, now: float, *, limit: int, base: int, maximum: int) -> int:
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
            failures += 1
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
        # Global lock serializes both budgets across replicas. A rotating source
        # cannot evade the deployment-wide ceiling by creating fresh buckets.
        with self.transaction("audit-budget") as execute:
            admitted = []
            for bucket, limit in (("audit:global", 100), ("audit:source:" + source, 3)):
                row = execute("SELECT failures, window_start FROM api_auth_failure_limits WHERE source = ?", (bucket,)).fetchone()
                count, start = row if row and now - row[1] < 60 else (0, now)
                if count >= limit:
                    return False
                admitted.append((bucket, count + 1, start, now))
            for values in admitted:
                execute(
                    """INSERT INTO api_auth_failure_limits VALUES (?, ?, 0, ?, 0, ?)
                    ON CONFLICT (source) DO UPDATE SET failures=excluded.failures,
                    window_start=excluded.window_start, updated_at=excluded.updated_at""",
                    values,
                )
        return True


class SQLiteAuthFailureStore(AuthFailureStore):
    def __init__(self, path: str = ":memory:") -> None:
        if path != ":memory:":
            descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
            os.close(descriptor)
            os.chmod(path, 0o600)
        self._connection = sqlite3.connect(path, check_same_thread=False, timeout=5)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute(_TABLE)
        self._connection.commit()
        self._connection.execute("PRAGMA busy_timeout=400")
        self._lock = threading.Lock()

    @contextmanager
    def transaction(self, source: str):
        try:
            with self._lock:
                conn = self._connection
                conn.execute("BEGIN IMMEDIATE")
                with conn:
                    yield conn.execute
        except sqlite3.OperationalError as exc:
            if getattr(exc, "sqlite_errorcode", 0) & 0xFF in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
                raise TimeoutError("Authentication database capacity exhausted") from exc
            raise


class PostgresAuthFailureStore(AuthFailureStore):
    """Share the existing Postgres rate-limit pool, with transaction locks."""

    def __init__(self, rate_limit_store: Any) -> None:
        self._pool = rate_limit_store._pool

        with self._pool.connection() as conn:
            if ensure_postgres_schema_version(conn, "auth_failure_limits"):
                conn.execute(_TABLE)

    @contextmanager
    def transaction(self, source: str):
        try:
            with self._pool.connection(timeout=0.4) as conn:
                conn.execute("SET LOCAL statement_timeout = '400ms'")
                conn.execute("SET LOCAL lock_timeout = '400ms'")
                conn.execute("SELECT pg_advisory_xact_lock(%s)", (PostgresRateLimitStore._advisory_key("auth:" + source),))

                def execute(sql, parameters):
                    return conn.execute(sql.replace("?", "%s"), parameters)

                yield execute
        except Exception as exc:  # broad-except: Classify optional-driver contention without importing it in SQLite installations.
            if getattr(exc, "sqlstate", None) in {"55P03", "57014"} or type(exc).__name__ == "PoolTimeout":
                raise TimeoutError("Authentication database capacity exhausted") from exc
            raise
