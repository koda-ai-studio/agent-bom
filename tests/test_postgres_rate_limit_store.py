"""Postgres-backed sliding-window rate limiting, on a private Postgres cluster."""

from __future__ import annotations

import socket
import threading
import time
from collections import Counter

import pytest

from agent_bom.api.middleware import InMemoryRateLimitStore, PostgresRateLimitStore
from tests.test_auth_failure_processes import postgres, workdir  # noqa: F401 - fixtures


def _fixed_window_count(key: str, now: float, *, window_seconds: int, timestamps: list[float]) -> int:
    """Simulate the old fixed-window Postgres counter for comparison tests."""
    window_started = int(now // window_seconds) * window_seconds
    return sum(1 for ts in timestamps if int(ts // window_seconds) * window_seconds == window_started)


def test_sliding_window_blocks_cross_bucket_burst_that_fixed_window_allowed():
    """Three hits at the end of bucket A must still count against a hit one second into bucket B."""
    window = 60
    bucket_a_start = 1_700_000_040.0
    first_bucket_end = bucket_a_start + 59.0
    next_bucket_start = bucket_a_start + 60.0

    memory = InMemoryRateLimitStore(window_seconds=window)
    for _ in range(3):
        memory.hit("tenant:read", first_bucket_end)

    fourth_count, _ = memory.hit("tenant:read", next_bucket_start)
    assert fourth_count == 4

    timestamps = [first_bucket_end, first_bucket_end, first_bucket_end, next_bucket_start]
    assert _fixed_window_count("tenant:read", next_bucket_start, window_seconds=window, timestamps=timestamps) == 1


@pytest.fixture
def pool(postgres):  # noqa: F811
    from psycopg_pool import ConnectionPool

    with ConnectionPool(postgres.admin_url, min_size=1, max_size=8, kwargs={"autocommit": True}) as connections:
        yield connections


def _hits(pool) -> list[tuple[str, float]]:
    with pool.connection() as conn:
        return [(row[0], float(row[1])) for row in conn.execute("SELECT bucket_key, hit_at FROM api_rate_limit_hits")]


def test_postgres_store_matches_the_in_memory_sliding_window(pool):
    store = PostgresRateLimitStore(window_seconds=60, pool=pool)
    memory = InMemoryRateLimitStore(window_seconds=60)
    base = 1_700_000_100.0
    for offset in (0.0, 5.0, 10.0, 55.0, 61.0, 130.0):
        assert store.hit("tenant:scan", base + offset) == memory.hit("tenant:scan", base + offset)


def test_postgres_store_prunes_stale_hits(pool):
    store = PostgresRateLimitStore(window_seconds=60, pool=pool)
    base = 1_700_000_200.0
    store.hit("tenant:read", base)
    store.hit("tenant:other", base)
    # Within a prune interval a bucket prunes only itself.
    store._next_global_prune = base + 1_000
    store.hit("tenant:read", base + 120.0)
    assert sorted(_hits(pool)) == [("tenant:other", base), ("tenant:read", base + 120.0)]
    # The periodic table-wide prune trims buckets that never return.
    store._next_global_prune = 0.0
    store.hit("tenant:read", base + 240.0)
    assert _hits(pool) == [("tenant:read", base + 240.0)]


def test_postgres_store_consumes_below_limit(pool):
    store = PostgresRateLimitStore(window_seconds=60, pool=pool)
    base = 1_700_000_300.0
    assert store.consume_if_below("tenant:credit", base, 2) == (True, 1, int(base + 60))
    assert store.consume_if_below("tenant:credit", base + 1, 2) == (True, 2, int(base + 60))
    assert store.consume_if_below("tenant:credit", base + 2, 2) == (False, 2, int(base + 60))
    assert store.count("tenant:credit", base + 2) == 2
    assert store.count("tenant:credit", base + 61) == 1


@pytest.mark.parametrize("key", ["ip:x'; DROP TABLE api_rate_limit_hits; --", "tenant:a\\b", "tenant:é'\"$$"])
def test_bucket_keys_are_stored_exactly_as_given(pool, key):
    store = PostgresRateLimitStore(window_seconds=60, pool=pool)
    assert store.hit(key, 1_700_000_400.0)[0] == 1
    assert store.count(key, 1_700_000_400.0) == 1
    assert _hits(pool) == [(key, 1_700_000_400.0)]


def test_concurrent_sessions_never_admit_past_the_limit(pool):
    store = PostgresRateLimitStore(window_seconds=60, pool=pool)
    base = 1_700_000_600.0
    results: list[bool] = []
    lock = threading.Lock()

    def consume(offset: int) -> None:
        for n in range(5):
            accepted = store.consume_if_below("tenant:shared", base + offset * 0.01 + n * 0.001, 10)[0]
            with lock:
                results.append(accepted)

    threads = [threading.Thread(target=consume, args=(n,)) for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert Counter(results) == {True: 10, False: 30}


def test_the_database_bounds_each_operation_and_leaves_the_connection_clean(pool):
    from agent_bom.api.rate_limit_store import bounded_round_trip

    with pool.connection() as conn:
        started = time.monotonic()
        with pytest.raises(Exception) as raised:
            bounded_round_trip(conn, [("SELECT pg_sleep(%s)", (2,))])
        assert getattr(raised.value, "sqlstate", None) == "57014"
        assert time.monotonic() - started < 1.5
        # Rolled back, and the bounds ended with the transaction.
        assert conn.execute("SHOW statement_timeout").fetchone() == ("0",)


def test_a_held_budget_lock_is_bounded_by_the_lock_timeout(pool):
    store = PostgresRateLimitStore(window_seconds=60, pool=pool)
    with pool.connection() as holder:
        holder.execute("BEGIN")
        holder.execute("SELECT pg_advisory_xact_lock(%s)", (store._advisory_key("tenant:held"),))
        started = time.monotonic()
        with pytest.raises(Exception) as raised:
            store.consume_if_below("tenant:held", 1_700_000_700.0, 5)
        holder.execute("ROLLBACK")
    # Lock and statement bounds are equal, so either may cancel the wait first.
    assert getattr(raised.value, "sqlstate", None) in {"55P03", "57014"}
    assert time.monotonic() - started < 1.5


def test_a_hit_is_one_network_round_trip(postgres):  # noqa: F811
    from psycopg_pool import ConnectionPool

    # Every reply from the server is held back 300 ms, so each round trip costs at least that.
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    delay = [0.0]

    def pump(source, target, replies):
        while data := source.recv(65536):
            if replies and delay[0]:
                time.sleep(delay[0])
            target.sendall(data)

    def accept():
        client, _ = listener.accept()
        upstream = socket.create_connection(("127.0.0.1", postgres.port))
        threading.Thread(target=pump, args=(client, upstream, False), daemon=True).start()
        threading.Thread(target=pump, args=(upstream, client, True), daemon=True).start()

    threading.Thread(target=accept, daemon=True).start()
    url = postgres.admin_url.replace(f":{postgres.port}/", f":{listener.getsockname()[1]}/") + "?sslmode=disable"
    with ConnectionPool(url, min_size=1, max_size=1, kwargs={"autocommit": True}) as proxied:
        store = PostgresRateLimitStore(window_seconds=60, pool=proxied)
        store.hit("tenant:trip", 1_700_000_800.0)
        delay[0] = 0.3
        started = time.monotonic()
        assert store.hit("tenant:trip", 1_700_000_801.0)[0] == 2
        elapsed = time.monotonic() - started
        delay[0] = 0.0
    assert 0.3 <= elapsed < 0.6, elapsed
