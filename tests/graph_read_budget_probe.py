"""SQLite work counters for the API budget tests; no SQL values are recorded."""

from __future__ import annotations

import sqlite3
import threading
import time
from collections import Counter
from typing import Any


class DatabaseWork:
    def __init__(self) -> None:
        self.counts: Counter[str] = Counter()
        self.lock = threading.Lock()

    def add(self, key: str, value: int = 1) -> None:
        with self.lock:
            self.counts[key] += value

    def snapshot(self) -> dict[str, int]:
        with self.lock:
            return dict(self.counts)

    def instrument(self, monkeypatch: Any) -> None:
        original = sqlite3.connect
        work = self

        class Cursor(sqlite3.Cursor):
            def execute(self, sql: str, parameters: Any = ()) -> Any:
                started = time.perf_counter_ns()
                try:
                    return super().execute(sql, parameters)
                finally:
                    work.add("statements")
                    work.add("execute_ns", time.perf_counter_ns() - started)

            def executemany(self, sql: str, parameters: Any) -> Any:
                started = time.perf_counter_ns()
                try:
                    return super().executemany(sql, parameters)
                finally:
                    work.add("batch_calls")
                    work.add("execute_ns", time.perf_counter_ns() - started)

            def fetchone(self) -> Any:
                row = super().fetchone()
                work.add("fetched_rows", int(row is not None))
                return row

            def fetchmany(self, size: int | None = None) -> Any:
                rows = super().fetchmany() if size is None else super().fetchmany(size)
                work.add("fetched_rows", len(rows))
                return rows

            def fetchall(self) -> Any:
                rows = super().fetchall()
                work.add("fetched_rows", len(rows))
                return rows

            def __next__(self) -> Any:
                row = super().__next__()
                work.add("fetched_rows")
                return row

        class Connection(sqlite3.Connection):
            def cursor(self, factory: Any = Cursor) -> Any:
                return super().cursor(factory=factory)

            def execute(self, sql: str, parameters: Any = ()) -> Any:
                return self.cursor().execute(sql, parameters)

            def executemany(self, sql: str, parameters: Any) -> Any:
                return self.cursor().executemany(sql, parameters)

        def connect(*args: Any, **kwargs: Any) -> Any:
            kwargs.setdefault("factory", Connection)
            return original(*args, **kwargs)

        monkeypatch.setattr(sqlite3, "connect", connect)
