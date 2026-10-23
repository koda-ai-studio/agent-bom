"""Postgres-backed operator advisories and re-match state with tenant RLS."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from agent_bom.api.operator_advisory_store import _record, _tenant
from agent_bom.api.postgres_common import ConnectionPool, _ensure_tenant_rls, _get_pool, _tenant_connection
from agent_bom.api.storage_schema import ensure_postgres_schema_version


class PostgresOperatorAdvisoryStore:
    """Tenant-scoped operator advisories; Alembic owns the schema on configured deployments."""

    def __init__(self, pool: ConnectionPool | None = None) -> None:
        self._pool = pool or _get_pool()
        with self._pool.connection() as conn:
            if ensure_postgres_schema_version(conn, "operator_advisories"):
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS operator_advisories (tenant_id TEXT NOT NULL, advisory_id TEXT NOT NULL, "
                    "updated_at TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (tenant_id, advisory_id))"
                )
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS operator_advisory_rematch_state (tenant_id TEXT PRIMARY KEY, "
                    "updated_at TEXT NOT NULL, data TEXT NOT NULL)"
                )
                for table in ("operator_advisories", "operator_advisory_rematch_state"):
                    _ensure_tenant_rls(conn, table, "tenant_id")
                conn.commit()

    def put(self, tenant_id: str, advisory: Mapping[str, Any]) -> dict[str, Any]:
        record = _record(advisory)
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                "INSERT INTO operator_advisories (tenant_id, advisory_id, updated_at, data) VALUES (%s, %s, %s, %s) "
                "ON CONFLICT (tenant_id, advisory_id) DO UPDATE SET updated_at = EXCLUDED.updated_at, data = EXCLUDED.data",
                (_tenant(tenant_id), str(record["id"]), record["updated_at"], json.dumps(record, sort_keys=True)),
            )
            conn.commit()
        return record

    def get(self, tenant_id: str, advisory_id: str) -> dict[str, Any] | None:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                "SELECT data FROM operator_advisories WHERE tenant_id = %s AND advisory_id = %s", (_tenant(tenant_id), advisory_id)
            ).fetchone()
        return json.loads(row[0]) if row else None

    def list(self, tenant_id: str) -> list[dict[str, Any]]:
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                "SELECT data FROM operator_advisories WHERE tenant_id = %s ORDER BY advisory_id", (_tenant(tenant_id),)
            ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def delete(self, tenant_id: str, advisory_id: str) -> bool:
        with _tenant_connection(self._pool) as conn:
            cursor = conn.execute(
                "DELETE FROM operator_advisories WHERE tenant_id = %s AND advisory_id = %s", (_tenant(tenant_id), advisory_id)
            )
            conn.commit()
            return bool(cursor.rowcount > 0)

    def get_rematch_state(self, tenant_id: str) -> dict[str, Any] | None:
        with _tenant_connection(self._pool) as conn:
            row = conn.execute("SELECT data FROM operator_advisory_rematch_state WHERE tenant_id = %s", (_tenant(tenant_id),)).fetchone()
        return json.loads(row[0]) if row else None

    def put_rematch_state(self, tenant_id: str, state: Mapping[str, Any]) -> None:
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                "INSERT INTO operator_advisory_rematch_state (tenant_id, updated_at, data) VALUES (%s, %s, %s) "
                "ON CONFLICT (tenant_id) DO UPDATE SET updated_at = EXCLUDED.updated_at, data = EXCLUDED.data",
                (_tenant(tenant_id), datetime.now(timezone.utc).isoformat(), json.dumps(dict(state), sort_keys=True, default=str)),
            )
            conn.commit()
