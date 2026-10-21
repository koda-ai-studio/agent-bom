"""SQLite JSON persistence shared by the four evidence registries."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from typing import Any, Generic, TypeVar

from agent_bom.api.storage.sql import SQLiteBackend

Record = TypeVar("Record")


class SQLiteRegistryStore(Generic[Record]):
    """Adapters own fixed SQL identifiers, schema, tenant predicates and decoding."""

    table: str
    columns: tuple[str, ...]
    ddl: tuple[str, ...]

    def __init__(self, db_path: str = "agent_bom.db") -> None:
        self._backend = SQLiteBackend(db_path)
        self._init_db()

    @property
    def _conn(self) -> sqlite3.Connection:
        return self._backend._conn()

    def _init_db(self) -> None:
        self._backend.bootstrap(self.table, {"sqlite": self.ddl})

    def _decode(self, raw: str) -> Record:
        raise NotImplementedError

    def _put_payload(self, values: tuple[Any, ...], payload: Mapping[str, Any]) -> None:
        columns = (*self.columns, "data")
        with self._backend.transaction() as tx:
            tx.execute(
                f"INSERT OR REPLACE INTO {self.table} ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})",  # nosec B608 - identifiers are fixed by the adapter
                (*values, json.dumps(payload, sort_keys=True)),
            )

    def _get(self, predicate: str, params: tuple[Any, ...]) -> Record | None:
        row = self._conn.execute(f"SELECT data FROM {self.table} WHERE {predicate}", params).fetchone()  # nosec B608 - fixed adapter SQL
        return self._decode(row[0]) if row else None

    def _list(self, predicate: str, params: tuple[Any, ...], *, order: str, limit: int | None = None, offset: int = 0) -> list[Record]:
        query = f"SELECT data FROM {self.table} WHERE {predicate} ORDER BY {order}"  # nosec B608 - fixed adapter SQL
        if limit is not None:
            query += " LIMIT ? OFFSET ?"
            params = (*params, limit, offset)
        return [self._decode(row[0]) for row in self._conn.execute(query, params).fetchall()]
