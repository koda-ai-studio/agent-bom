"""Graph startup survives a reader racing the initial WAL transition."""

import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.db.graph_store import open_graph_db


@pytest.mark.parametrize("api_store", [False, True])
def test_graph_startup_retries_real_wal_contention(tmp_path, monkeypatch, api_store):
    path = tmp_path / "graph.db"
    real_connect = sqlite3.connect
    reader = real_connect(path)
    reader.execute("CREATE TABLE retained (value TEXT)")
    reader.execute("INSERT INTO retained VALUES ('preserved')")
    reader.commit()
    reader.execute("BEGIN")
    reader.execute("SELECT * FROM retained").fetchall()
    busy_seen = threading.Event()

    class ObservedConnection(sqlite3.Connection):
        def execute(self, statement, *args, **kwargs):
            try:
                return super().execute(statement, *args, **kwargs)
            except sqlite3.OperationalError as exc:
                if statement == "PRAGMA journal_mode=WAL" and exc.sqlite_errorcode == sqlite3.SQLITE_BUSY:
                    busy_seen.set()
                raise

    def connect(*args, **kwargs):
        if str(args[0]) != str(path):
            return real_connect(*args, **kwargs)
        kwargs.update(timeout=0.01, factory=ObservedConnection)
        return real_connect(*args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", connect)

    def initialize():
        if api_store:
            conn = SQLiteGraphStore(path)._open_rw_conn()
            try:
                assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 10
                return conn.execute("PRAGMA journal_mode").fetchone()[0]
            finally:
                conn.close()
        with open_graph_db(path) as conn:
            assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 10
            return conn.execute("PRAGMA journal_mode").fetchone()[0]

    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            result = pool.submit(initialize)
            try:
                assert busy_seen.wait(5), "the reader did not hold WAL startup"
            finally:
                reader.rollback()
            assert result.result(timeout=5) == "wal"
        assert reader.execute("SELECT value FROM retained").fetchone() == ("preserved",)
    finally:
        reader.close()


@pytest.mark.parametrize("api_store", [False, True])
@pytest.mark.parametrize("code", [sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_LOCKED, sqlite3.SQLITE_BUSY])
def test_graph_startup_closes_connection_on_failure(tmp_path, monkeypatch, api_store, code):
    from agent_bom.storage import sqlite_wal

    real_connect = sqlite3.connect
    path = tmp_path / "graph.db"
    opened = []

    class FailedConnection(sqlite3.Connection):
        closed = False
        attempts = 0

        def execute(self, statement, *args, **kwargs):
            if statement == "PRAGMA journal_mode=WAL":
                self.attempts += 1
                error = sqlite3.OperationalError("injected graph startup failure")
                error.sqlite_errorcode = code
                raise error
            return super().execute(statement, *args, **kwargs)

        def close(self):
            assert super().execute("PRAGMA busy_timeout").fetchone()[0] == 10000
            self.closed = True
            super().close()

    def connect(*args, **kwargs):
        if str(args[0]) != str(path):
            return real_connect(*args, **kwargs)
        conn = real_connect(*args, **kwargs, factory=FailedConnection)
        opened.append(conn)
        return conn

    monkeypatch.setattr(sqlite3, "connect", connect)
    if code == sqlite3.SQLITE_BUSY:
        clock = iter([0.0, 9.0, 10.0])
        real_time = sqlite_wal.time
        owner = threading.get_ident()
        # Only this test thread consumes the fake deadline; unrelated graph
        # startup and process-wide timing retain their real clocks.
        monkeypatch.setattr(
            sqlite_wal,
            "time",
            SimpleNamespace(
                monotonic=lambda: next(clock) if threading.get_ident() == owner else real_time.monotonic(),
                sleep=lambda seconds: None if threading.get_ident() == owner else real_time.sleep(seconds),
            ),
        )

    def background_graph_startup():
        with open_graph_db(tmp_path / "unrelated.db") as conn:
            assert conn.execute("SELECT 1").fetchone()[0] == 1

    # Retained API workers can initialize another database while this fixture
    # injects an error. That connection must retain real SQLite behavior.
    with ThreadPoolExecutor(max_workers=1) as pool:
        pool.submit(background_graph_startup).result(timeout=5)

    with pytest.raises(sqlite3.OperationalError, match="injected graph startup failure"):
        if api_store:
            SQLiteGraphStore(path)._open_rw_conn()
        else:
            with open_graph_db(path):
                pytest.fail("startup must propagate errors or exhausted contention")
    assert len(opened) == 1
    assert opened[0].attempts == (2 if code == sqlite3.SQLITE_BUSY else 1)
    assert opened[0].closed
