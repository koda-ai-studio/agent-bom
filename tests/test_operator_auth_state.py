"""Auth failure state survives processes and escalates without key-based lockout."""

from contextlib import contextmanager

import pytest


def test_sqlite_writer_contention_is_not_a_store_outage(tmp_path):
    import sqlite3

    from agent_bom.api.auth_failure_store import SQLiteAuthFailureStore

    path = str(tmp_path / "busy-auth.db")
    store = SQLiteAuthFailureStore(path)
    with sqlite3.connect(path) as blocker:
        blocker.execute("BEGIN IMMEDIATE")
        with pytest.raises(TimeoutError):
            store.record("192.0.2.1", 100, limit=3, base=10, maximum=60)
        # Admission reads answer every authenticating caller and take no write lock.
        assert store.remaining("192.0.2.2", 100) == 0
    assert store.record("192.0.2.1", 100, limit=3, base=10, maximum=60) == 0


def test_postgres_auth_operations_bound_pool_and_sql_waits():
    from agent_bom.api.auth_failure_store import PostgresAuthFailureStore

    queries = []

    class Connection:
        def execute(self, sql, parameters=()):
            queries.append(sql)

    class Pool:
        @contextmanager
        def connection(self, *, timeout):
            assert timeout == 0.4
            yield Connection()

    store = PostgresAuthFailureStore.__new__(PostgresAuthFailureStore)
    store._pool = Pool()
    with store.transaction("192.0.2.1"):
        pass
    assert queries[:2] == ["SET LOCAL statement_timeout = '400ms'", "SET LOCAL lock_timeout = '400ms'"]


@pytest.mark.parametrize("sqlstate", ["55P03", "57014"])
def test_postgres_auth_contention_is_not_a_store_outage(sqlstate):
    from agent_bom.api.auth_failure_store import PostgresAuthFailureStore

    class BusyError(Exception):
        pass

    error = BusyError()
    error.sqlstate = sqlstate

    class Pool:
        @contextmanager
        def connection(self, **kwargs):
            raise error
            yield

    store = PostgresAuthFailureStore.__new__(PostgresAuthFailureStore)
    store._pool = Pool()
    with pytest.raises(TimeoutError):
        with store.transaction("192.0.2.1"):
            pass


def test_sqlite_shared_backoff_and_expiry(tmp_path):
    from agent_bom.api.auth_failure_store import SQLiteAuthFailureStore

    path = str(tmp_path / "limits.db")
    first, second = SQLiteAuthFailureStore(path), SQLiteAuthFailureStore(path)
    for _ in range(3):
        first.record("192.0.2.1", 100, limit=3, base=10, maximum=60)
    assert second.remaining("192.0.2.1", 101) == 9
    assert second.remaining("192.0.2.2", 101) == 0
    assert second.remaining("192.0.2.1", 111) == 0
    for _ in range(3):
        second.record("192.0.2.1", 111, limit=3, base=10, maximum=60)
    assert first.remaining("192.0.2.1", 112) == 19
    assert first.remaining("192.0.2.1", 4000) == 0


def test_audit_budget_is_shared_and_bounded(tmp_path):
    from agent_bom.api.auth_failure_store import SQLiteAuthFailureStore

    store = SQLiteAuthFailureStore(str(tmp_path / "limits.db"))
    assert sum(store.audit_allowed(f"192.0.2.{i}", 100) for i in range(400)) <= 100
    assert sum(store.audit_allowed("198.51.100.1", 200) for _ in range(400)) <= 3


def test_suppressed_source_receipts_do_not_exhaust_other_sources(tmp_path):
    from agent_bom.api.auth_failure_store import SQLiteAuthFailureStore

    store = SQLiteAuthFailureStore(str(tmp_path / "limits.db"))
    assert sum(store.audit_allowed("192.0.2.1", 100) for _ in range(100)) == 3
    assert sum(store.audit_allowed(f"198.51.100.{i}", 100) for i in range(100)) == 97
