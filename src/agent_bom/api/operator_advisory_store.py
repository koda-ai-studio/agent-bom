"""Tenant-scoped persistence for operator-declared advisories and re-match state.

In-memory for tests, SQLite for single-node durability, Postgres with tenant
RLS for multi-replica control planes (see ``postgres_operator_advisory``).
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any, Protocol

from agent_bom.api.storage_schema import ensure_sqlite_schema_version


def _tenant(tenant_id: str) -> str:
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise ValueError("an explicit tenant is required")
    return tenant_id.strip()


def _record(advisory: Mapping[str, Any]) -> dict[str, Any]:
    record = json.loads(json.dumps(dict(advisory), default=str))
    record["updated_at"] = datetime.now(timezone.utc).isoformat()
    return record


class OperatorAdvisoryStore(Protocol):
    def put(self, tenant_id: str, advisory: Mapping[str, Any]) -> dict[str, Any]: ...
    def get(self, tenant_id: str, advisory_id: str) -> dict[str, Any] | None: ...
    def list(self, tenant_id: str) -> list[dict[str, Any]]: ...
    def delete(self, tenant_id: str, advisory_id: str) -> bool: ...
    def get_rematch_state(self, tenant_id: str) -> dict[str, Any] | None: ...
    def put_rematch_state(self, tenant_id: str, state: Mapping[str, Any]) -> None: ...


class InMemoryOperatorAdvisoryStore:
    def __init__(self) -> None:
        self._rows: dict[tuple[str, str], dict[str, Any]] = {}
        self._state: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def put(self, tenant_id: str, advisory: Mapping[str, Any]) -> dict[str, Any]:
        record = _record(advisory)
        with self._lock:
            self._rows[(_tenant(tenant_id), str(record["id"]))] = record
        return json.loads(json.dumps(record))

    def get(self, tenant_id: str, advisory_id: str) -> dict[str, Any] | None:
        row = self._rows.get((_tenant(tenant_id), advisory_id))
        return json.loads(json.dumps(row)) if row is not None else None

    def list(self, tenant_id: str) -> list[dict[str, Any]]:
        tenant = _tenant(tenant_id)
        return [json.loads(json.dumps(row)) for (owner, _id), row in sorted(self._rows.items()) if owner == tenant]

    def delete(self, tenant_id: str, advisory_id: str) -> bool:
        with self._lock:
            return self._rows.pop((_tenant(tenant_id), advisory_id), None) is not None

    def get_rematch_state(self, tenant_id: str) -> dict[str, Any] | None:
        state = self._state.get(_tenant(tenant_id))
        return json.loads(json.dumps(state)) if state is not None else None

    def put_rematch_state(self, tenant_id: str, state: Mapping[str, Any]) -> None:
        self._state[_tenant(tenant_id)] = json.loads(json.dumps(dict(state), default=str))


class SQLiteOperatorAdvisoryStore:
    def __init__(self, db_path: str = "agent_bom.db") -> None:
        self._db_path = db_path
        self._local = threading.local()
        ensure_sqlite_schema_version(self._conn, "operator_advisories")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS operator_advisories (
                tenant_id TEXT NOT NULL,
                advisory_id TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                data TEXT NOT NULL,
                PRIMARY KEY (tenant_id, advisory_id)
            )
            """
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS operator_advisory_rematch_state "
            "(tenant_id TEXT PRIMARY KEY, updated_at TEXT NOT NULL, data TEXT NOT NULL)"
        )
        self._conn.commit()

    @property
    def _conn(self) -> sqlite3.Connection:
        if getattr(self._local, "conn", None) is None:
            self._local.conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._local.conn.execute("PRAGMA journal_mode=WAL")
        conn: sqlite3.Connection = self._local.conn
        return conn

    def put(self, tenant_id: str, advisory: Mapping[str, Any]) -> dict[str, Any]:
        record = _record(advisory)
        self._conn.execute(
            "INSERT OR REPLACE INTO operator_advisories (tenant_id, advisory_id, updated_at, data) VALUES (?, ?, ?, ?)",
            (_tenant(tenant_id), str(record["id"]), record["updated_at"], json.dumps(record, sort_keys=True)),
        )
        self._conn.commit()
        return record

    def get(self, tenant_id: str, advisory_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT data FROM operator_advisories WHERE tenant_id = ? AND advisory_id = ?", (_tenant(tenant_id), advisory_id)
        ).fetchone()
        return json.loads(row[0]) if row else None

    def list(self, tenant_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT data FROM operator_advisories WHERE tenant_id = ? ORDER BY advisory_id", (_tenant(tenant_id),)
        ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def delete(self, tenant_id: str, advisory_id: str) -> bool:
        cursor = self._conn.execute(
            "DELETE FROM operator_advisories WHERE tenant_id = ? AND advisory_id = ?", (_tenant(tenant_id), advisory_id)
        )
        self._conn.commit()
        return cursor.rowcount > 0

    def get_rematch_state(self, tenant_id: str) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT data FROM operator_advisory_rematch_state WHERE tenant_id = ?", (_tenant(tenant_id),)).fetchone()
        return json.loads(row[0]) if row else None

    def put_rematch_state(self, tenant_id: str, state: Mapping[str, Any]) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO operator_advisory_rematch_state (tenant_id, updated_at, data) VALUES (?, ?, ?)",
            (_tenant(tenant_id), datetime.now(timezone.utc).isoformat(), json.dumps(dict(state), sort_keys=True, default=str)),
        )
        self._conn.commit()
