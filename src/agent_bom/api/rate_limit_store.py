"""Rate limit store."""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from typing import Any

_logger = logging.getLogger(__name__)


class InMemoryRateLimitStore:
    """Process-local sliding-window limiter state."""

    _MAX_ENTRIES = 10_000

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
            timestamps = [t for t in self._hits.get(key, []) if now - t < self._window]
            timestamps.append(now)
            self._hits[key] = timestamps
            reset_at = int((timestamps[0] if timestamps else now) + self._window)
            return len(timestamps), reset_at

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


class PostgresRateLimitStore:
    """Shared sliding-window limiter backed by Postgres for horizontal scaling."""

    def __init__(self, window_seconds: int = 60, pool: Any = None) -> None:
        self._window = window_seconds
        if pool is None:
            from agent_bom.api.postgres_common import _get_pool

            pool = _get_pool()
        self._pool = pool
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

    def hit(self, key: str, now: float) -> tuple[int, int]:
        """Record a request and return (hit_count, reset_epoch)."""
        window_start = now - self._window
        with self._pool.connection() as conn:
            # Trim stale hits opportunistically to keep the table bounded.
            conn.execute(
                "DELETE FROM api_rate_limit_hits WHERE hit_at < %s",
                (window_start,),
            )
            conn.execute(
                "INSERT INTO api_rate_limit_hits (bucket_key, hit_at) VALUES (%s, %s)",
                (key, now),
            )
            row = conn.execute(
                """
                SELECT COUNT(*), MIN(hit_at)
                FROM api_rate_limit_hits
                WHERE bucket_key = %s AND hit_at >= %s
                """,
                (key, window_start),
            ).fetchone()
        count = int(row[0]) if row and row[0] is not None else 1
        oldest = float(row[1]) if row and row[1] is not None else now
        reset_at = int(oldest + self._window)
        return count, reset_at

    @staticmethod
    def _advisory_key(key: str) -> int:
        digest = hashlib.sha256(f"rate-limit:{key}".encode()).digest()
        return int.from_bytes(digest[:8], "big", signed=True)

    def consume_if_below(self, key: str, now: float, limit: int) -> tuple[bool, int, int]:
        """Atomically consume one unit using a transaction advisory lock."""

        window_start = now - self._window
        with self._pool.connection() as conn:
            conn.execute("SELECT pg_advisory_xact_lock(%s)", (self._advisory_key(key),))
            conn.execute("DELETE FROM api_rate_limit_hits WHERE bucket_key = %s AND hit_at < %s", (key, window_start))
            row = conn.execute(
                "SELECT COUNT(*), MIN(hit_at) FROM api_rate_limit_hits WHERE bucket_key = %s AND hit_at >= %s",
                (key, window_start),
            ).fetchone()
            current = int(row[0]) if row and row[0] is not None else 0
            oldest = float(row[1]) if row and row[1] is not None else now
            accepted = current < limit
            if accepted:
                conn.execute("INSERT INTO api_rate_limit_hits (bucket_key, hit_at) VALUES (%s, %s)", (key, now))
                current += 1
                if current == 1:
                    oldest = now
        return accepted, current, int(oldest + self._window)

    def count(self, key: str, now: float) -> int:
        """Return current sliding-window usage without consuming a unit."""

        window_start = now - self._window
        with self._pool.connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM api_rate_limit_hits WHERE bucket_key = %s AND hit_at >= %s",
                (key, window_start),
            ).fetchone()
        return int(row[0]) if row and row[0] is not None else 0
