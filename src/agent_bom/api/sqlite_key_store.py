"""Durable SQLite API key store for single-node deployments."""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone

from agent_bom.api.api_key_record import ApiKey, verify_api_key
from agent_bom.api.storage.sqlite_connection import open_wal_connection
from agent_bom.api.storage_schema import ensure_sqlite_schema_version
from agent_bom.rbac import Role

_COLUMNS = (
    "tenant_id, key_id, key_hash, key_salt, key_prefix, name, role, scopes, created_at, expires_at, "
    "revoked_at, rotation_overlap_until, replacement_key_id, scim_subject_id, owner, principal_id"
)
_INSERT = f"INSERT INTO api_keys ({_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"  # nosec B608 - fixed column list; values are bound
_UPSERT = _INSERT + (  # nosec B608 - fixed column list; values are bound
    """
    ON CONFLICT (tenant_id, key_id) DO UPDATE SET
      key_hash = excluded.key_hash,
      key_salt = excluded.key_salt,
      key_prefix = excluded.key_prefix,
      name = excluded.name,
      role = excluded.role,
      scopes = excluded.scopes,
      created_at = excluded.created_at,
      expires_at = excluded.expires_at,
      revoked_at = excluded.revoked_at,
      rotation_overlap_until = excluded.rotation_overlap_until,
      replacement_key_id = excluded.replacement_key_id,
      scim_subject_id = excluded.scim_subject_id,
      owner = excluded.owner,
      principal_id = excluded.principal_id
"""
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SQLiteKeyStore:
    """SQLite-backed API key store; only scrypt hashes and salts are persisted."""

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._local = threading.local()
        self._write_lock = threading.Lock()
        self._init_db()

    @property
    def _conn(self) -> sqlite3.Connection:
        conn: sqlite3.Connection | None = getattr(self._local, "conn", None)
        if conn is None:
            conn = open_wal_connection(self._db_path)
            self._local.conn = conn
        return conn

    def _init_db(self) -> None:
        conn = self._conn
        ensure_sqlite_schema_version(conn, "api_keys")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS api_keys (
                tenant_id TEXT NOT NULL,
                key_id TEXT NOT NULL,
                key_hash TEXT NOT NULL,
                key_salt TEXT NOT NULL,
                key_prefix TEXT NOT NULL,
                name TEXT NOT NULL,
                role TEXT NOT NULL,
                scopes TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL,
                expires_at TEXT,
                revoked_at TEXT,
                rotation_overlap_until TEXT,
                replacement_key_id TEXT,
                scim_subject_id TEXT,
                owner TEXT,
                principal_id TEXT,
                PRIMARY KEY (tenant_id, key_id)
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys (key_prefix)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_principal ON api_keys (tenant_id, principal_id)")
        conn.commit()

    @staticmethod
    def _params(key: ApiKey) -> tuple[object, ...]:
        return (
            key.tenant_id,
            key.key_id,
            key.key_hash,
            key.key_salt,
            key.key_prefix,
            key.name,
            key.role.value,
            json.dumps(key.scopes),
            key.created_at,
            key.expires_at,
            key.revoked_at,
            key.rotation_overlap_until,
            key.replacement_key_id,
            key.scim_subject_id,
            key.owner,
            key.principal_id,
        )

    @staticmethod
    def _row_to_key(row: tuple) -> ApiKey:
        return ApiKey(
            tenant_id=row[0],
            key_id=row[1],
            key_hash=row[2],
            key_salt=row[3],
            key_prefix=row[4],
            name=row[5],
            role=Role(row[6]),
            scopes=json.loads(row[7] or "[]"),
            created_at=row[8],
            expires_at=row[9],
            revoked_at=row[10],
            rotation_overlap_until=row[11],
            replacement_key_id=row[12],
            scim_subject_id=row[13],
            owner=row[14],
            principal_id=row[15],
        )

    def _write(self, sql: str, params: tuple[object, ...]) -> int:
        with self._write_lock:
            cursor = self._conn.execute(sql, params)
            self._conn.commit()
            return int(cursor.rowcount)

    def add(self, key: ApiKey) -> None:
        self._write(_UPSERT, self._params(key))

    def provision_tenant_key(self, key: ApiKey, *, team_name: str) -> None:
        """Insert a new tenant's first key; an existing id is never overwritten."""
        del team_name
        self._write(_INSERT, self._params(key))

    def remove(self, key_id: str) -> bool:
        sql = "UPDATE api_keys SET revoked_at = ?, rotation_overlap_until = NULL WHERE key_id = ? AND revoked_at IS NULL"
        return self._write(sql, (_now(), key_id)) > 0

    def revoke_by_principal_id(self, principal_id: str, tenant_id: str | None = None) -> list[str]:
        if not principal_id:
            return []
        where = "principal_id = ? AND revoked_at IS NULL"
        params: tuple[object, ...] = (principal_id,)
        if tenant_id is not None:
            where += " AND tenant_id = ?"
            params = (principal_id, tenant_id)
        with self._write_lock:
            rows = self._conn.execute(f"SELECT key_id FROM api_keys WHERE {where}", params).fetchall()  # nosec B608 - fixed column list; values are bound
            self._conn.execute(f"UPDATE api_keys SET revoked_at = ?, rotation_overlap_until = NULL WHERE {where}", (_now(), *params))  # nosec B608 - fixed column list; values are bound
            self._conn.commit()
        return [row[0] for row in rows]

    def mark_rotating(self, key_id: str, *, replacement_key_id: str, overlap_until: str) -> bool:
        sql = "UPDATE api_keys SET replacement_key_id = ?, rotation_overlap_until = ? WHERE key_id = ? AND revoked_at IS NULL"
        return self._write(sql, (replacement_key_id, overlap_until, key_id)) > 0

    def get(self, key_id: str) -> ApiKey | None:
        row = self._conn.execute(f"SELECT {_COLUMNS} FROM api_keys WHERE key_id = ?", (key_id,)).fetchone()  # nosec B608 - fixed column list; values are bound
        return self._row_to_key(row) if row else None

    def list_keys(self, tenant_id: str | None = None) -> list[ApiKey]:
        if tenant_id is None:
            rows = self._conn.execute(f"SELECT {_COLUMNS} FROM api_keys ORDER BY created_at DESC").fetchall()  # nosec B608 - fixed column list; values are bound
        else:
            rows = self._conn.execute(
                f"SELECT {_COLUMNS} FROM api_keys WHERE tenant_id = ? ORDER BY created_at DESC",  # nosec B608 - fixed column list; values are bound
                (tenant_id,),
            ).fetchall()
        return [self._row_to_key(row) for row in rows]

    def delete_tenant(self, tenant_id: str) -> int:
        return self._write("DELETE FROM api_keys WHERE tenant_id = ?", (tenant_id,))

    def verify(self, raw_key: str) -> ApiKey | None:
        rows = self._conn.execute(f"SELECT {_COLUMNS} FROM api_keys WHERE key_prefix = ?", (raw_key[:12],)).fetchall()  # nosec B608 - fixed column list; values are bound
        return verify_api_key(raw_key, [self._row_to_key(row) for row in rows])

    def has_keys(self) -> bool:
        return self._conn.execute("SELECT 1 FROM api_keys WHERE revoked_at IS NULL LIMIT 1").fetchone() is not None
